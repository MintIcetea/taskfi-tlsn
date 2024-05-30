use std::fmt::Debug;

#[derive(serde::Deserialize)]
pub struct ServerResponse<T> {
    pub data: T,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct ServerError<'a> {
    pub error: &'a str,
}

impl<'a> ServerError<'a> {
    pub fn new(message: &'a str) -> Self {
        ServerError { error: message }
    }
}

impl<'a> Debug for ServerError<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}
