use std::{
    error::Error,
    fmt::{Debug, Display},
};

#[derive(serde::Deserialize)]
pub struct ServerResponse<T> {
    pub data: T,
}

#[derive(serde::Deserialize, serde::Serialize, Clone, Debug)]
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

impl Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl Error for ServerError {}
