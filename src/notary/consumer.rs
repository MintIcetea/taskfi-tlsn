use core::time;
use std::{collections::HashSet, sync::Arc};

use crate::{
    config::{read_config, NotaryConfig, Settings},
    errors::ServerError,
    hyper::RequestMethod,
    notary::{
        model::{NotarizeResponse, QueueRequest},
        notary::{request_notarization, NOTARY_MAX_RECV, NOTARY_MAX_SENT},
    },
    r2::R2Manager,
};

use aws_sdk_sqs::{config::SharedCredentialsProvider, Client};
use http_body_util::BodyExt;
use hyper::Request;
use hyper_util::rt::TokioIo;
use reqwest;
use tlsn_core::proof::TlsProof;
use tlsn_prover::tls::{
    state::{Closed, Notarize},
    Prover, ProverConfig, ProverError,
};
use tokio::{sync::Mutex, task::JoinHandle};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::warn;

macro_rules! error {
    ($message:expr, $err:expr) => {
        tracing::error!("{}, error: {:?}", $message, $err);
    };
}

const QUEUE_QUERY_INTERVAL: time::Duration = time::Duration::from_millis(10000);

pub async fn consume(processing_requests: Arc<Mutex<HashSet<String>>>) {
    let config = read_config().expect("Failed to load queue config");

    let mut interval = tokio::time::interval(QUEUE_QUERY_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let credentials = aws_credential_types::Credentials::from_keys(
        &config.queue.access_key_id,
        &config.queue.secret_access_key,
        None,
    );
    let sqs_config = aws_config::SdkConfig::builder()
        .behavior_version(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(config.queue.region.clone()))
        .endpoint_url(&config.queue.endpoint_url)
        .credentials_provider(SharedCredentialsProvider::new(credentials))
        .build();
    let sqs_client = Client::new(&sqs_config);

    loop {
        interval.tick().await;

        // Get a single message from queue to process
        match sqs_client
            .receive_message()
            .wait_time_seconds(5)
            .max_number_of_messages(1)
            .queue_url(config.queue.queue_url.clone())
            .send()
            .await
        {
            Ok(resp) => {
                let messages = resp.messages();

                if messages.len() == 0 {
                    // No message or empty message
                    continue;
                }

                if sqs_client
                    .delete_message()
                    .queue_url(config.queue.queue_url.clone())
                    .receipt_handle(messages[0].receipt_handle().unwrap())
                    .send()
                    .await
                    .is_err()
                {
                    continue;
                }

                let body = messages[0].body();
                if body.is_none() {
                    // Empty message
                    continue;
                }

                match serde_json::from_str::<QueueRequest>(&body.unwrap()) {
                    Ok(message) => {
                        // Lock the mutex to read and insert request id to map
                        let mut locked_requests = processing_requests.lock().await;

                        if locked_requests.contains(&message.headers.request_id) {
                            // Request ID is currently processing by other worker
                            // The mutex will be out of scope by continue
                            continue;
                        }
                        locked_requests.insert(message.headers.request_id.clone());
                        drop(locked_requests);

                        // Notarize the request
                        let _ = notarize(config.clone(), message.clone()).await;

                        // Lock the mutex and remove request id to map
                        let mut locked_requests = processing_requests.lock().await;
                        locked_requests.remove(&message.headers.request_id);
                        drop(locked_requests);
                    }
                    Err(err) => {
                        // Can't serialize the message
                        error!("Can't deserialize request", err);
                    }
                }
            }
            Err(err) => {
                error!("Failed to get queue messages", err);
            }
        }
    }
}

struct NotarizeHeaders {
    id: String,
    host: String,
    path: String,
    method: RequestMethod,
    auth: String,
}

#[derive(serde::Deserialize)]
pub struct NotarizeRequest {
    pub headers: String,
    pub body: String,
}

pub async fn notarize(
    config: Settings,
    queue_request: QueueRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("Processing request ID {}", queue_request.headers.request_id);

    let mut responses: Vec<String> = Vec::new();

    for subrequest in queue_request.requests {
        let method = match RequestMethod::try_from(subrequest.method) {
            Ok(method) => method,
            Err(err) => return Err(Box::new(ServerError::new(&err))),
        };

        let notarize_headers = NotarizeHeaders {
            id: queue_request.headers.request_id.clone(),
            auth: queue_request.authorization.clone(),
            host: subrequest.host,
            path: subrequest.path,
            method,
        };
        let request_body = subrequest.body;

        match single_notarize(config.notary.clone(), notarize_headers, request_body).await {
            Ok(response) => responses.push(response),
            Err(err) => return Err(err),
        }
    }

    let responses_str = match serde_json::to_string(&responses) {
        Ok(response_str) => response_str,
        Err(err) => {
            error!("Failed to serialize response", err);
            return Err(Box::new(err));
        }
    };

    // Call TaskFi worker to update the data
    let queue_response = NotarizeResponse {
        success: true,
        responses: responses_str.clone(),
    };
    let response = reqwest::Client::new()
        .post(format!(
            "{}:{}/api/credentials/update",
            config.worker.host, config.worker.port
        ))
        .json(&queue_response)
        .header("x-tlsn-request-id", queue_request.headers.request_id)
        .header(
            "x-tlsn-wallet-address",
            queue_request.headers.wallet_address,
        )
        .header("x-tlsn-subject-id", queue_request.headers.subject_id)
        .header("x-tlsn-provider", queue_request.headers.provider)
        .send()
        .await;

    if response.is_err() {
        error!(
            "Failed to send notarized response to TaskFi worker",
            response.as_ref().err()
        );
        return Err(Box::new(response.err().unwrap()));
    }

    Ok(())
}

async fn background_notarize(
    request_id: String,
    prover_task: JoinHandle<Result<Prover<Closed>, ProverError>>,
) {
    let proofs = start_notarize(prover_task).await;
    let file_name = format!("{}.json", request_id);
    store_proofs(
        file_name.as_str(),
        serde_json::to_string(&proofs).unwrap().as_bytes(),
    )
    .await;

    tracing::info!("Proof uploaded to R2: file_name: {}", file_name);
}

async fn single_notarize(
    notary: NotaryConfig,
    notarize_headers: NotarizeHeaders,
    request_body: String,
) -> Result<String, Box<dyn std::error::Error>> {
    let notary_host: &str = &notary.host;
    let notary_port: u16 = notary.port;

    let (notary_socket, session_id) = match request_notarization(notary_host, notary_port).await {
        Ok((notary_socket, session_id)) => (notary_socket, session_id),
        Err(err) => {
            error!(
                format!(
                    "Failed to request notarization from notary server at {}:{}",
                    notary_host, notary_port
                ),
                err
            );
            return Err(err);
        }
    };

    // A Prover configuration
    let config = match ProverConfig::builder()
        .id(session_id)
        .max_recv_data(NOTARY_MAX_SENT)
        .max_sent_data(NOTARY_MAX_RECV)
        .server_dns(notarize_headers.host.clone())
        .build()
    {
        Ok(config) => config,
        Err(err) => {
            error!("Failed to build prover configuration", err);
            return Err(Box::new(err));
        }
    };

    // Create a Prover and set it up with the Notary
    // This will set up the MPC backend prior to connecting to the server.
    let prover = match Prover::new(config).setup(notary_socket.compat()).await {
        Ok(prover) => prover,
        Err(err) => {
            error!("Failed to setup the prover", err);
            return Err(Box::new(err));
        }
    };

    // Connect to the Server via TCP. This is the TLS client socket.
    let client_socket =
        match tokio::net::TcpStream::connect((notarize_headers.host.clone(), 443)).await {
            Ok(client_socket) => client_socket,
            Err(err) => {
                error!("Failed to connect to the notary server", err);
                return Err(Box::new(err));
            }
        };

    // Bind the Prover to the server connection.
    // The returned `mpc_tls_connection` is an MPC TLS connection to the Server: all data written
    // to/read from it will be encrypted/decrypted using MPC with the Notary.
    let (mpc_tls_connection, prover_fut) = match prover.connect(client_socket.compat()).await {
        Ok((mpc_tls_connection, prover_fut)) => (mpc_tls_connection, prover_fut),
        Err(err) => {
            error!("Failed to bind the prover to the notary", err);
            return Err(Box::new(err));
        }
    };
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    // Spawn the Prover task to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the MPC TLS connection
    let (mut request_sender, connection) =
        match hyper::client::conn::http1::handshake(mpc_tls_connection).await {
            Ok((request_sender, connection)) => (request_sender, connection),
            Err(err) => {
                error!("Failed to attach HTTP client to MPC connection", err);
                return Err(Box::new(err));
            }
        };

    // Spawn the HTTP task to be run concurrently
    tokio::spawn(connection);

    let request_uri = format!(
        "https://{}/{}",
        &notarize_headers.host, &notarize_headers.path
    );
    // Build a simple HTTP request with common headers
    tracing::info!(
        "Notary server initialized. MPC_TLS connection between client and prover \
            initialized. Start requesting to {}",
        request_uri
    );
    let request_method = match RequestMethod::try_from(notarize_headers.method) {
        Ok(method) => method,
        Err(err) => {
            error!("Invalid request method", err);
            return Err(Box::new(err));
        }
    };

    let request = match Request::builder()
        .uri(&request_uri)
        .method(request_method.as_ref())
        .header("Host", &notarize_headers.host)
        .header("authorization", &notarize_headers.auth)
        .header("Accept", "*/*")
        .header("User-Agent", "taskfi-vc")
        .body(request_body)
    {
        Ok(request) => request,
        Err(err) => {
            error!("Failed to build notarize request", err);
            return Err(Box::new(err));
        }
    };

    let response = match request_sender.send_request(request).await {
        Ok(response) => response,
        Err(err) => {
            error!(format!("Request to {} failed", &request_uri), err);
            return Err(Box::new(err));
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
    ) {
        Ok(response_data) => response_data,
        Err(err) => {
            error!("Failed to read the raw response", err);
            return Err(Box::new(err));
        }
    };

    // Only generate proofs when the request is successful
    if !response_status.is_client_error() && !response_status.is_server_error() {
        let request_id = notarize_headers.id.clone().to_string();
        background_notarize(request_id, prover_task).await;
    } else {
        warn!(
            "Response NOT OK: status {}, body: {}",
            response_status, response_data
        );

        // Close running task
        prover_task.abort();
    };

    Ok(response_data)
}

async fn start_notarize(prover_task: JoinHandle<Result<Prover<Closed>, ProverError>>) -> String {
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
