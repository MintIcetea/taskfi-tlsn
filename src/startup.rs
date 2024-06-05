use std::net::TcpListener;

use actix_web::{dev::Server, web, App, HttpServer};
use tracing_actix_web::TracingLogger;

use crate::{
    r2::R2Manager,
    routes::{health_check::handle_health_check, notarize::handle_notarize_v2},
    telemetry::{init_subscriber, setup_subscriber},
};

pub async fn run(listener: TcpListener, r2: R2Manager) -> Result<Server, std::io::Error> {
    let subsciber = setup_subscriber();
    init_subscriber(subsciber);

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
