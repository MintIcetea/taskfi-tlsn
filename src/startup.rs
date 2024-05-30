use std::net::TcpListener;

use actix_web::{dev::Server, web, App, HttpServer};

use crate::{
    r2::R2Manager,
    routes::{health_check::handle_health_check, notarize::handle_notarize_v2},
};

pub async fn run(listener: TcpListener, r2: R2Manager) -> Result<Server, std::io::Error> {
    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(r2.clone()))
            .route("health_check", web::get().to(handle_health_check))
            .route("notarize", web::post().to(handle_notarize_v2))
    })
    .listen(listener)?
    .run();

    Ok(server)
}
