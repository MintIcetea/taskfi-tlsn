use hyper::Method;

pub struct RequestMethod(hyper::Method);

impl RequestMethod {
    pub fn new(method: Method) -> Self {
        RequestMethod(method)
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
