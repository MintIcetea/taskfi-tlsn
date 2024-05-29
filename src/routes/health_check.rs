use actix_web::{HttpResponse, Responder};

pub async fn handle_health_check() -> impl Responder {
    HttpResponse::Ok()
}
