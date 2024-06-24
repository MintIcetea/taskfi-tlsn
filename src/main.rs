use std::{cmp::min, collections::HashSet, net::TcpListener, sync::Arc};

use config::read_config;
use notary::consumer::consume;
use r2::R2Manager;
use startup::run;

use tokio::{runtime, sync::Mutex};

mod config;
mod errors;
mod hyper;
mod notary;
mod r2;
mod routes;
mod startup;
mod telemetry;

// Use jemallocator to avoid memory leaking
#[cfg(all(not(windows), not(target_env = "musl")))]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let app_config = read_config().unwrap_or_else(|err| {
        panic!(
            "Failed to read application configurations with errors {:?}",
            err
        )
    });

    let r2 = R2Manager::new(&app_config.r2).await;
    let notary_config = app_config.notary;

    let app_address = format!(
        "{}:{}",
        app_config.application.host, app_config.application.port
    );

    println!("Starting server at http://{}", app_address);

    let num_threads = std::thread::available_parallelism().unwrap().get();
    let rt = runtime::Builder::new_multi_thread()
        .worker_threads(min(num_threads, app_config.application.max_thread_limit))
        .enable_all()
        .build()
        .unwrap();

    let processing_requests = Arc::new(Mutex::new(HashSet::new()));
    for _i in 0..num_threads {
        let processing_requests = processing_requests.clone();
        rt.spawn(async move { consume(processing_requests).await });
    }

    let listener = TcpListener::bind(app_address.clone())
        .unwrap_or_else(|_| panic!("Failed to listen on {}", app_address));
    run(listener, r2, notary_config).await.unwrap().await
}
