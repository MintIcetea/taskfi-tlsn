use std::net::TcpListener;

use actix_web::{dev::Server, web, App, HttpServer};

use crate::routes::health_check::handle_health_check;

pub async fn run(listener: TcpListener) -> Result<Server, std::io::Error> {
    let server = HttpServer::new(move || {
        App::new().route("health_check", web::get().to(handle_health_check))
    })
    .listen(listener)?
    .run();

    Ok(server)
}
