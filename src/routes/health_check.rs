use actix_web::{web, HttpResponse, Responder};

use crate::r2::R2Manager;

pub async fn handle_health_check() -> impl Responder {
    HttpResponse::Ok()
}
