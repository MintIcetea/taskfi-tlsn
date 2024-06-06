use std::fmt::Debug;

#[derive(serde::Deserialize)]
pub struct ServerResponse<T> {
    pub data: T,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct ServerError {
    pub error: String,
}

impl ServerError {
    pub fn new(message: &str) -> Self {
        ServerError {
            error: message.to_string(),
        }
    }
}

impl Debug for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}
