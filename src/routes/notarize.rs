use crate::{
    errors::ServerError,
    notary::{run_notary, DEFAULT_MAX_RECV_LIMIT, DEFAULT_MAX_SENT_LIMIT},
    r2::R2Manager,
};
use actix_web::{http::header::HeaderMap, web, HttpRequest, HttpResponse};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::json;
use tlsn_core::proof::TlsProof;
use tlsn_prover::tls::{state::Notarize, Prover, ProverConfig};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

#[derive(serde::Deserialize, serde::Serialize)]
struct NotarizeHeaders<'a> {
    id: &'a str,
    host: &'a str,
    path: &'a str,
    method: &'a str,
}

pub async fn handle_notarize_v2(data: web::Data<R2Manager>, request: HttpRequest) -> HttpResponse {
    let r2 = data.clone();

    let headers = request.headers();
    let notarize_headers = match extract_headers(headers) {
        Ok(headers) => headers,
        Err(err) => return HttpResponse::BadRequest().body(json!(err).to_string()),
    };

    // Separate this as not all APIs require authorization
    let auth_header = match extract_header(headers, "x-tlsn-auth") {
        Ok(header) => header,
        Err(err) => return HttpResponse::BadRequest().body(json!(err).to_string()),
    };
    println!(
        "Headers extracted: notarizer headers:{} + auth header {}",
        json!(notarize_headers).to_string(),
        auth_header
    );

    let (prover_socket, notary_socket) = tokio::io::duplex(1 << 16);

    // Start a local simple notary service
    tokio::spawn(run_notary(notary_socket.compat()));

    // A Prover configuration
    let config = ProverConfig::builder()
        .id("example")
        .max_recv_data(DEFAULT_MAX_RECV_LIMIT)
        .max_sent_data(DEFAULT_MAX_SENT_LIMIT)
        .server_dns(notarize_headers.host)
        .build()
        .unwrap();

    // Create a Prover and set it up with the Notary
    // This will set up the MPC backend prior to connecting to the server.
    let prover = Prover::new(config)
        .setup(prover_socket.compat())
        .await
        .unwrap();

    // Connect to the Server via TCP. This is the TLS client socket.
    let client_socket = tokio::net::TcpStream::connect((notarize_headers.host, 443))
        .await
        .unwrap();

    // Bind the Prover to the server connection.
    // The returned `mpc_tls_connection` is an MPC TLS connection to the Server: all data written
    // to/read from it will be encrypted/decrypted using MPC with the Notary.
    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    // Spawn the Prover task to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the MPC TLS connection
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection)
            .await
            .unwrap();

    // Spawn the HTTP task to be run concurrently
    tokio::spawn(connection);

    // Build a simple HTTP request with common headers
    println!(
        "Requesting to https://{}/{}",
        notarize_headers.host, notarize_headers.path
    );
    let request_builder = Request::builder()
        .uri(format!(
            "https://{}/{}",
            notarize_headers.host, notarize_headers.path
        ))
        .method(notarize_headers.method)
        .header("Host", notarize_headers.host)
        .header("Authorization", format!("Bearer {}", auth_header))
        .header("Accept", "*/*")
        .header("User-Agent", "TaskFi ID")
        .body(String::from(""))
        .unwrap();

    let response = match request_sender.send_request(request_builder).await {
        Ok(response) => response,
        Err(_) => {
            return HttpResponse::InternalServerError().body(
                json!(ServerError::new(
                    format!("Request to {} failed", notarize_headers.host).as_str()
                ))
                .to_string(),
            )
        }
    };
    assert!(response.status() == StatusCode::OK);
    // The Prover task should be done now, so we can grab the Prover.
    let prover = prover_task.await.unwrap().unwrap();

    // Prepare for notarization.
    let prover = prover.start_notarize();
    let proof = build_proof_without_redactions(prover).await;

    let file_name = format!("{}.json", notarize_headers.id);
    r2.upload(
        file_name.as_str(),
        serde_json::to_string_pretty(&proof).unwrap().as_bytes(),
        Some("immutable"),
        Some("multipart/form-data"),
    )
    .await;

    HttpResponse::Ok().body(serde_json::to_string(&proof).unwrap())
}

async fn build_proof_without_redactions(mut prover: Prover<Notarize>) -> TlsProof {
    let sent_len = prover.sent_transcript().data().len();
    let recv_len = prover.recv_transcript().data().len();

    let builder = prover.commitment_builder();
    let sent_commitment = builder.commit_sent(&(0..sent_len)).unwrap();
    let recv_commitment = builder.commit_recv(&(0..recv_len)).unwrap();

    // Finalize, returning the notarized session
    let notarized_session = prover.finalize().await.unwrap();

    // Create a proof for all committed data in this session
    let mut proof_builder = notarized_session.data().build_substrings_proof();

    // Reveal all the public ranges
    proof_builder.reveal_by_id(sent_commitment).unwrap();
    proof_builder.reveal_by_id(recv_commitment).unwrap();

    let substrings_proof = proof_builder.build().unwrap();

    TlsProof {
        session: notarized_session.session_proof(),
        substrings: substrings_proof,
    }
}

fn extract_headers(headers: &HeaderMap) -> Result<NotarizeHeaders, ServerError> {
    let host = extract_header(headers, "x-tlsn-host")?;
    let path = extract_header(headers, "x-tlsn-path")?;
    let method = extract_header(headers, "x-tlsn-method")?;
    let request_id = extract_header(headers, "x-tlsn-id")?;

    Ok(NotarizeHeaders {
        id: request_id,
        host,
        path,
        method,
    })
}

fn extract_header<'a>(headers: &'a HeaderMap, key: &str) -> Result<&'a str, ServerError<'a>> {
    let header = match headers.get(key) {
        Some(header) => header,
        None => {
            return Err(ServerError::new("header not found"));
        }
    };

    match header.to_str() {
        Ok(header) => Ok(header),
        Err(err) => {
            println!("Cannot parsed {} header with error {:?}", key, err);
            return Err(ServerError::new("header invalid"));
        }
    }
}
