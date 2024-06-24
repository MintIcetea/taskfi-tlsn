use serde::{Deserialize, Serialize};

#[derive(Deserialize, Clone)]
pub struct QueueSubRequest {
    pub host: String,
    pub method: String,
    pub path: String,
    pub body: String,
}

#[derive(Deserialize, Clone)]
pub struct QueueRequest {
    pub authorization: String,
    pub headers: QueueRequestHeaders,
    pub requests: Vec<QueueSubRequest>,
}

#[derive(Serialize, Debug)]
pub struct NotarizeResponse {
    pub success: bool,
    pub responses: String,
}

#[derive(Deserialize, Clone)]
pub struct QueueRequestHeaders {
    pub request_id: String,
    pub wallet_address: String,
    pub subject_id: String,
    pub provider: String,
}
