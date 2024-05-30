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
