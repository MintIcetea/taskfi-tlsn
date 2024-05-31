use std::net::TcpListener;

use actix_web::{dev::Server, web, App, HttpServer};
use tracing_actix_web::TracingLogger;

use crate::{
    r2::R2Manager,
    routes::{health_check::handle_health_check, notarize::handle_notarize_v2},
};

pub async fn run(listener: TcpListener, r2: R2Manager) -> Result<Server, std::io::Error> {
    // tracing::subscriber::set_global_default(subscriber).expect("Failed to init tracing");
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

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
