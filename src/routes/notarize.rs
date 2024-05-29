use actix_web::{http::header::HeaderMap, HttpRequest, HttpResponse, Responder};
use serde_json::json;
use tlsn_prover::tls::{state::Setup, Prover, ProverConfig, ProverConfigBuilder};
use tokio::io::DuplexStream;
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::{
    errors::ServerError,
    notary::{run_notary, DEFAULT_MAX_RECV_LIMIT, DEFAULT_MAX_SENT_LIMIT},
};

struct NotarizeHeaders<'a> {
    host: &'a str,
    path: &'a str,
    method: &'a str,
}

async fn handle_notarize(request: HttpRequest) -> impl Responder {
    let headers = request.headers();
    let notarize_headers = match extract_headers(headers) {
        Ok(headers) => headers,
        Err(err) => return HttpResponse::BadRequest().body(json!(err).to_string()),
    };

    // Separate this as not all APIs require authz
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

    HttpResponse::Ok().finish()
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
            return Err(ServerError::new(
                format!("{} header not found", key).as_str(),
            ))
        }
    };

    match header.to_str() {
        Ok(header) => Ok(header),
        Err(err) => {
            println!("Cannot parsed {} header with error {:?}", key, err);
            return Err(ServerError::new(format!("{} header invalid", key).as_str()));
        }
    }
}
