use std::net::TcpListener;

use config::read_config;
use r2::R2Manager;
use startup::run;

mod config;
mod errors;
mod notary;
mod r2;
mod routes;
mod startup;
mod telemetry;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let app_config = read_config().unwrap_or_else(|err| {
        panic!(
            "Failed to read application configurations with errors {:?}",
            err
        )
    });

    let r2 = R2Manager::new(&app_config.r2).await;

    let app_address = format!(
        "{}:{}",
        app_config.application.host, app_config.application.port
    );

    println!("Starting server at http://{}", app_address);

    let listener = TcpListener::bind(app_address.clone())
        .expect(format!("Failed to listen on {}", app_address).as_str());
    run(listener, r2).await.unwrap().await
}
