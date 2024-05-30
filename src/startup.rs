use std::net::TcpListener;

use actix_web::{dev::Server, web, App, HttpServer};

use crate::routes::{
    health_check::handle_health_check,
    notarize::{handle_notarize, handle_notarize_v2},
};

pub async fn run(listener: TcpListener) -> Result<Server, std::io::Error> {
    let server = HttpServer::new(move || {
        App::new()
            .route("health_check", web::get().to(handle_health_check))
            .route("notarize", web::post().to(handle_notarize_v2))
    })
    .listen(listener)?
    .run();

    Ok(server)
}
