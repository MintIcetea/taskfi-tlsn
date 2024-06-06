use std::str::FromStr;

use crate::{
    config::read_config,
    errors::ServerError,
    notary::{request_notarization, NOTARY_MAX_SENT, NOTARY_MAX_RECV},
    r2::R2Manager,
};
use actix_web::{
    body::BoxBody,
    http::{header::HeaderMap, Method, StatusCode},
    HttpRequest, HttpResponse,
};
use http_body_util::BodyExt;
use hyper::Request;
use hyper_util::rt::TokioIo;
use serde_json::json;
use tlsn_core::proof::TlsProof;
use tlsn_prover::tls::{
    state::{Closed, Notarize},
    Prover, ProverConfig, ProverError,
};
use tokio::task::JoinHandle;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::warn;
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
    auth: String,
}

macro_rules! internal_server_error {
    ($message:expr, $err:expr) => {
        tracing::error!("{}, error: {:?}", $message, $err);
        return HttpResponse::InternalServerError().body(
            json!(ServerError::new(format!("{:?}", $err).as_str())).to_string());
    }
}

pub async fn handle_notarize_v2(
    request: HttpRequest,
    bytes: actix_web::web::Bytes,
) -> HttpResponse {

    // Start request validation

    let headers = request.headers();
    let notarize_headers = match extract_headers(headers) {
        Ok(headers) => headers,
        Err(err) => return HttpResponse::BadRequest().body(json!(err).to_string()),
    };

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

    match hyper::Method::from_str(&notarize_headers.method) {
        Ok(_) => (),
        Err(_) => {
            return HttpResponse::BadRequest().body(
                json!(ServerError::new(
                    format!(
                        "Invalid request method {}", request.method().to_string()
                    )
                    .as_str()
                ))
                .to_string(),
            );
        }
    }

    info!(
        "Receive incoming request: headers: {}, body: {}",
        json!(notarize_headers),
        request_body
    );

    // Start notarizing data

    let app_config = match read_config() {
        Ok(app_config) => app_config,
        Err(err) => {
            internal_server_error!("Failed to read app config", err);
        },
    };
    let notary_host: &str = &app_config.notary.host;
    let notary_port: u16 = app_config.notary.port;

    let (notary_socket, session_id) = match request_notarization(
        notary_host,
        notary_port,
    ).await {
        Ok((notary_socket, session_id)) => (notary_socket, session_id),
        Err(err) => {
            internal_server_error!(format!("Failed to request notarization from \
                notary server at {}:{}", notary_host, notary_port), err);
        }
    };

    // A Prover configuration
    let config = match ProverConfig::builder()
        .id(session_id)
        .max_recv_data(NOTARY_MAX_SENT)
        .max_sent_data(NOTARY_MAX_RECV)
        .server_dns(notarize_headers.host.clone()).build() {
            Ok(config) => config,
            Err(err) => {
                internal_server_error!("Failed to build prover configuration", err);
            }
        };

    // Create a Prover and set it up with the Notary
    // This will set up the MPC backend prior to connecting to the server.
    let prover = match Prover::new(config).setup(notary_socket.compat()).await {
        Ok(prover) => prover,
        Err(err) => {
            internal_server_error!("Failed to setup the prover", err);
        }
    };

    // Connect to the Server via TCP. This is the TLS client socket.
    let client_socket = match tokio::net::TcpStream::connect((notarize_headers.host.clone(), 443)).await {
        Ok(client_socket) => client_socket,
        Err(err) => {
            internal_server_error!("Failed to connect to the notary server", err);
        }
    };

    // Bind the Prover to the server connection.
    // The returned `mpc_tls_connection` is an MPC TLS connection to the Server: all data written
    // to/read from it will be encrypted/decrypted using MPC with the Notary.
    let (mpc_tls_connection, prover_fut) = match prover.connect(client_socket.compat()).await {
        Ok((mpc_tls_connection, prover_fut)) => (mpc_tls_connection, prover_fut),
        Err(err) => {
            internal_server_error!("Failed to bind the prover to the notary", err);
        }
    };
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    // Spawn the Prover task to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the MPC TLS connection
    let (mut request_sender, connection) = match
        hyper::client::conn::http1::handshake(mpc_tls_connection).await {
            Ok((request_sender, connection)) => (request_sender, connection),
            Err(err) => {
                internal_server_error!("Failed to attach HTTP client to MPC connection", err);
            }
        };

    // Spawn the HTTP task to be run concurrently
    tokio::spawn(connection);

    let request_uri = format!(
        "https://{}/{}",
        &notarize_headers.host, &notarize_headers.path
    );
    // Build a simple HTTP request with common headers
    info!("Notary server initialized. MPC_TLS connection between client and prover \
        initialized. Start requesting to {}", request_uri);
    let request = match Request::builder()
        .uri(&request_uri)
        .method(hyper::Method::from_str(&notarize_headers.method).unwrap())
        .header("Host", &notarize_headers.host)
        .header("authorization", &notarize_headers.auth)
        .header("Accept", "*/*")
        .header("User-Agent", "TaskFi ID")
        .body(request_body) {
            Ok(request) => request,
            Err(err) => {
                internal_server_error!("Failed to build notarize request", err);
            }
        };

    let response = match request_sender.send_request(request).await {
        Ok(response) => response,
        Err(err) => {
            internal_server_error!(format!("Request to {} failed", &request_uri), err);
        }
    };

    // Read raw response
    let response_status = response.status();
    let response_data = match String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    ){
        Ok(response_data) => response_data,
        Err(err) => {
            internal_server_error!("Failed to read the raw response", err);
        }
    };

    // Only generate proofs when the request is successful
    if !response_status.is_client_error() && !response_status.is_server_error() {
        let request_id = notarize_headers.id.clone().to_string();
        tokio::spawn(background_notarize(request_id, prover_task));
    } else {
        warn!(
            "Response NOT OK: status {}, body: {}",
            response_status, response_data
        );

        // Close running task
        prover_task.abort();
    }

    // Return the response early
    HttpResponse::with_body(
        StatusCode::from_u16(response_status.as_u16()).unwrap(),
        BoxBody::new(response_data),
    )
}

async fn background_notarize(
    request_id: String,
    prover_task: JoinHandle<Result<Prover<Closed>, ProverError>>,
) {
    let proofs = notarize(prover_task).await;
    let file_name = format!("{}.json", request_id);
    store_proofs(
        file_name.as_str(),
        serde_json::to_string(&proofs).unwrap().as_bytes(),
    )
    .await;

    info!("Proof uploaded to R2: file_name: {}", file_name);
}

async fn notarize(prover_task: JoinHandle<Result<Prover<Closed>, ProverError>>) -> String {
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
    let auth = extract_header(headers, "authorization")?;

    Ok(NotarizeHeaders {
        id: request_id,
        host,
        path,
        method,
        auth,
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
