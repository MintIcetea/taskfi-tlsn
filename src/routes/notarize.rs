use actix_web::{http::header::HeaderMap, HttpRequest, HttpResponse, Responder};
use hyper::{client::conn, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::json;
use tlsn_core::proof::TlsProof;
use tlsn_prover::tls::{
    state::{Notarize, Setup},
    Prover, ProverConfig,
};
use tokio::io::DuplexStream;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use crate::{
    errors::ServerError,
    notary::{run_notary, DEFAULT_MAX_RECV_LIMIT, DEFAULT_MAX_SENT_LIMIT},
};

struct NotarizeHeaders<'a> {
    host: &'a str,
    path: &'a str,
    method: &'a str,
}

// TODO: Add notarize handler for other providers
// This currently only handle GitHub request
pub async fn handle_notarize(request: HttpRequest) -> impl Responder {
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

    // Setup prover and notary server

    let (prover_socket, notary_socket) = tokio::io::duplex(1 << 16);

    // Setup local notary server, connected to prover_socket
    tokio::spawn(run_notary(notary_socket.compat()));

    // Setup local prover
    let prover = match setup_prover(prover_socket, notarize_headers.host).await {
        Ok(prover) => prover,
        Err(error) => {
            return HttpResponse::InternalServerError().body(json!(error).to_string());
        }
    };

    // Setup MPC-TLS between client and prover
    let client_socket = match tokio::net::TcpStream::connect((notarize_headers.host, 443)).await {
        Ok(stream) => stream,
        Err(_) => {
            return HttpResponse::InternalServerError().body(
                json!(ServerError::new(
                    format!(
                        "Failed to establish TLS connection from client to {}",
                        notarize_headers.host
                    )
                    .as_str()
                ))
                .to_string(),
            )
        }
    };
    let (mpc_tls_connection, prover_fut) = match prover.connect(client_socket.compat()).await {
        Ok(connection) => connection,
        Err(_) => {
            return HttpResponse::InternalServerError().body(
                json!(ServerError::new(
                    "Failed to establish MPC-TLS connection between client, server, and prover",
                ))
                .to_string(),
            )
        }
    };

    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the TLS connection
    let (mut request_sender, connection) =
        conn::http1::handshake::<_, String>(TokioIo::new(mpc_tls_connection.compat()))
            .await
            .unwrap();

    // Spawn the HTTP task to be run concurrently
    tokio::spawn(connection);

    // Build a simple HTTP request with common headers
    let request_builder = Request::builder()
        .uri(format!(
            "https://{}{}",
            notarize_headers.path, notarize_headers.path
        ))
        .method(notarize_headers.method)
        .header("Authorization", auth_header)
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

    // Grab prover and build proof without redaction
    let prover = prover_task.await.unwrap().unwrap();
    let prover = prover.start_notarize();
    let proof = build_proof_without_redactions(prover).await;

    HttpResponse::Ok().body(json!(proof).to_string())
}

async fn setup_prover(conn: DuplexStream, host: &str) -> Result<Prover<Setup>, ServerError> {
    let config = match ProverConfig::builder()
        .id("cv3.xyz")
        .server_dns(host)
        .max_recv_data(DEFAULT_MAX_RECV_LIMIT)
        .max_sent_data(DEFAULT_MAX_SENT_LIMIT)
        .build()
    {
        Ok(config) => config,
        Err(error) => {
            println!("Failed to setup prover's config with error {:?}", error);
            return Err(ServerError::new("Internal server error"));
        }
    };

    match Prover::new(config).setup(conn.compat()).await {
        Ok(prover) => Ok(prover),
        Err(error) => {
            println!("Failed to setup prover with error {:?}", error);
            return Err(ServerError::new("Internal server error"));
        }
    }
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

    Ok(NotarizeHeaders { host, path, method })
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
