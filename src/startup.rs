use std::net::TcpListener;

use actix_web::{dev::Server, web, App, HttpServer};
use tracing::subscriber::set_global_default;
use tracing_actix_web::TracingLogger;
use tracing_bunyan_formatter::BunyanFormattingLayer;
use tracing_log::LogTracer;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};

use crate::{
    r2::R2Manager,
    routes::{health_check::handle_health_check, notarize::handle_notarize_v2},
};

pub async fn run(listener: TcpListener, r2: R2Manager) -> Result<Server, std::io::Error> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let format_layer = BunyanFormattingLayer::new("taskfi-tlsn".to_string(), std::io::stdout);
    let tracing_register = Registry::default().with(env_filter).with(format_layer);

    LogTracer::init().expect("Failed to init logger");
    set_global_default(tracing_register).expect("Failed to set subscriber");

    let server = HttpServer::new(move || {
        App::new()
            .wrap(TracingLogger::default())
            .app_data(web::Data::new(r2.clone()))
            .route("health_check", web::get().to(handle_health_check))
            .route("notarize", web::post().to(handle_notarize_v2))
    })
    .listen(listener)?
    .run();

    Ok(server)
}
