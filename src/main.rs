use std::net::TcpListener;

use config::read_config;
use startup::run;

mod config;
mod routes;
mod startup;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let app_config = read_config().unwrap_or_else(|err| {
        panic!(
            "Failed to read application configurations with errors {:?}",
            err
        )
    });

    let app_address = format!("{}:{}", app_config.host, app_config.port);

    println!("Starting server at http://{}", app_address);

    let listener = TcpListener::bind(app_address.clone())
        .expect(format!("Failed to listen on {}", app_address).as_str());
    run(listener).await.unwrap().await
}
