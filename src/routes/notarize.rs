use std::str::FromStr;

use crate::{
    config::read_config,
    errors::ServerError,
    notary::{run_notary, DEFAULT_MAX_RECV_LIMIT, DEFAULT_MAX_SENT_LIMIT},
    r2::R2Manager,
};
use actix_web::{
    http::{header::HeaderMap, Method},
    HttpRequest, HttpResponse,
};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::json;
use tlsn_core::proof::TlsProof;
use tlsn_prover::tls::{state::Notarize, Prover, ProverConfig};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing_log::log::info;

#[derive(serde::Serialize)]
struct NotarizeResponse {
    id: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct NotarizeHeaders {
    id: String,
    host: String,
    path: String,
    method: String,
}

pub async fn handle_notarize_v2(
    request: HttpRequest,
    bytes: actix_web::web::Bytes,
) -> HttpResponse {
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
    info!(
        "Headers extracted: notarizer headers:{} + auth header {}",
        json!(notarize_headers).to_string(),
        auth_header
    );

    let request_body = match String::from_utf8(bytes.to_vec()) {
        Ok(body) => body,
        Err(_) => {
            if request.method() != Method::GET {
                return HttpResponse::BadRequest().body(
                    json!(ServerError::new(
                        format!(
                            "Cannot execute {} request without request body",
                            request.method().to_string()
                        )
                        .as_str()
                    ))
                    .to_string(),
                );
            }

            String::from("")
        }
    };
    info!("Body extracted {}", json!(request_body).to_string());

    let request_id = notarize_headers.id.clone().to_string();

    tokio::spawn(background_notarize(
        notarize_headers,
        String::from(auth_header),
        request_body.clone(),
    ));

    HttpResponse::Accepted()
        .body(serde_json::to_string(&NotarizeResponse { id: request_id }).unwrap())
}

async fn background_notarize(headers: NotarizeHeaders, auth_header: String, request_body: String) {
    let proofs = notarize(&headers, auth_header.clone(), request_body.clone()).await;

    let file_name = format!("{}.json", headers.id);

    store_proofs(
        file_name.as_str(),
        serde_json::to_string(&proofs).unwrap().as_bytes(),
    )
    .await;
}

async fn notarize(headers: &NotarizeHeaders, auth_header: String, request_body: String) -> String {
    let (prover_socket, notary_socket) = tokio::io::duplex(1 << 16);

    // Start a local simple notary service
    tokio::spawn(run_notary(notary_socket.compat()));

    // A Prover configuration
    let config = ProverConfig::builder()
        .id("example")
        .max_recv_data(DEFAULT_MAX_RECV_LIMIT)
        .max_sent_data(DEFAULT_MAX_SENT_LIMIT)
        .server_dns(headers.host.clone())
        .build()
        .unwrap();

    // Create a Prover and set it up with the Notary
    // This will set up the MPC backend prior to connecting to the server.
    info!("Init local prover");
    let prover = Prover::new(config)
        .setup(prover_socket.compat())
        .await
        .unwrap();

    info!("Init TLS connection from client to server");
    // Connect to the Server via TCP. This is the TLS client socket.
    let client_socket = tokio::net::TcpStream::connect((headers.host.clone(), 443))
        .await
        .unwrap();

    // Bind the Prover to the server connection.
    // The returned `mpc_tls_connection` is an MPC TLS connection to the Server: all data written
    // to/read from it will be encrypted/decrypted using MPC with the Notary.
    info!("Binding Prover to the connection between local prover and server");
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
    info!("Requesting to https://{}/{}", headers.host, headers.path);
    let request_builder = Request::builder()
        .uri(format!("https://{}/{}", headers.host, headers.path))
        .method(hyper::Method::from_str(&headers.method).unwrap())
        .header("Host", headers.host.clone())
        .header("Authorization", format!("Bearer {}", auth_header))
        .header("Accept", "*/*")
        .header("User-Agent", "TaskFi ID")
        .body(request_body)
        .unwrap();

    let response = match request_sender.send_request(request_builder).await {
        Ok(response) => response,
        Err(_) => {
            tracing::error!("Request to {} failed", headers.host);
            return String::from("");
        }
    };
    assert!(response.status() == StatusCode::OK);
    info!(
        "Request to https://{}/{} came back OK",
        headers.host, headers.path
    );

    // The Prover task should be done now, so we can grab the Prover.
    let prover = prover_task.await.unwrap().unwrap();

    // Prepare for notarization.
    let prover = prover.start_notarize();
    let proof = build_proof_without_redactions(prover).await;

    serde_json::to_string(&proof).unwrap()
}

async fn store_proofs(file_name: &str, proofs: &[u8]) {
    // Connect to R2 with app config
    let app_config = read_config().unwrap_or_else(|err| {
        panic!(
            "Failed to read application configurations with errors {:?}",
            err
        )
    });

    let r2 = R2Manager::new(&app_config.r2).await;

    info!("Start uploading {} to R2", file_name);
    r2.upload(
        file_name,
        proofs,
        Some("immutable"),
        Some("multipart/form-data"),
    )
    .await;
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

fn extract_header<'a>(headers: &'a HeaderMap, key: &str) -> Result<String, ServerError<'a>> {
    let header = match headers.get(key) {
        Some(header) => header,
        None => {
            return Err(ServerError::new("header not found"));
        }
    };

    match header.to_str() {
        Ok(header) => Ok(String::from(header)),
        Err(err) => {
            println!("Cannot parsed {} header with error {:?}", key, err);
            return Err(ServerError::new("header invalid"));
        }
    }
}
