use std::str::FromStr;

use hyper::Method;

pub struct RequestMethod(hyper::Method);

impl TryFrom<String> for RequestMethod {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        let method = match Method::from_str(s.as_str()) {
            Ok(method) => method,
            Err(_) => return Err("Invalid request method".to_string()),
        };
        Ok(Self(method))
    }
}

impl AsRef<Method> for RequestMethod {
    fn as_ref(&self) -> &Method {
        &self.0
    }
}

impl serde::Serialize for RequestMethod {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}
