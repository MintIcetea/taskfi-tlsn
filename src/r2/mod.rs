use aws_sdk_s3::config::Credentials;
use aws_sdk_s3::config::SharedCredentialsProvider;
use std::sync::Arc;

use tracing::log::debug;
use tracing::log::error;
use tracing::log::info;

use aws_sdk_s3::config::Region;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::primitives::SdkBody;
use aws_sdk_s3::Client;

use crate::config::R2Config;

/// A struct providing most necessary APIs to work with Cloudflare R2 object storage.
#[derive(Debug, Clone)]
pub struct R2Manager {
    bucket_name: String,
    client: Arc<Client>,
}

impl R2Manager {
    /// Creates a new instance of R2Manager. The region is set to us-east-1 which aliases
    /// to auto. Read more here <https://developers.cloudflare.com/r2/api/s3/api/>.
    pub async fn new(config: &R2Config) -> R2Manager {
        let s3_credential = Credentials::from_keys(
            config.access_key.clone(),
            config.secret_access_key.clone(),
            None,
        );
        let s3_config = aws_config::load_from_env()
            .await
            .into_builder()
            .endpoint_url(config.uri.clone())
            .region(Region::new(config.region.clone()))
            .credentials_provider(SharedCredentialsProvider::new(s3_credential))
            .build();

        R2Manager {
            bucket_name: config.bucket_name.clone(),
            client: Arc::new(aws_sdk_s3::Client::new(&s3_config)),
        }
    }

    #[allow(dead_code)]
    /// Get the bucket name of the R2Manager.
    pub fn get_bucket_name(&self) -> &str {
        &self.bucket_name
    }

    #[allow(dead_code)]
    /// Create a bucket.
    pub async fn create_bucket(&self) {
        let create_bucket_request = self.client.create_bucket().bucket(&self.bucket_name);

        let result = create_bucket_request.send().await;

        if result.is_ok() {
            debug!("{:?}", result.unwrap());
            info!("Created successfully {}", self.bucket_name);
        } else {
            debug!("{:?}", result.unwrap_err());
            error!("Creation of {} failed.", self.bucket_name);
        }
    }

    #[allow(dead_code)]
    /// Delete a bucket.
    pub async fn delete_bucket(&self) {
        let delete_bucket_request = self.client.delete_bucket().bucket(&self.bucket_name);

        let result = delete_bucket_request.send().await;

        if result.is_ok() {
            debug!("{:?}", result.unwrap());
            info!("Deleted successfully {}", self.bucket_name);
        } else {
            debug!("{:?}", result.unwrap_err());
            error!("Deletion of {} failed.", self.bucket_name);
        }
    }

    #[allow(dead_code)]
    /// Upload an object in &[u8] format.
    /// ```
    /// let str_bytes = "Hello there!".as_bytes();
    /// r2manager.upload("my_object_name", str_bytes, Some("max-age:60"), Some("text/plain"));
    /// ```
    pub async fn upload(
        &self,
        object_name: &str,
        object_bytes: &[u8],
        cache_control: Option<&str>,
        content_type: Option<&str>,
    ) {
        let stream = ByteStream::new(SdkBody::from(object_bytes));
        let mut upload_request = self
            .client
            .put_object()
            .bucket(&self.bucket_name)
            .key(object_name)
            .body(stream);

        if let Some(cache_control) = cache_control {
            upload_request = upload_request.cache_control(cache_control);
        }

        if let Some(content_type) = content_type {
            upload_request = upload_request.content_type(content_type);
        }

        let result = upload_request.send().await;

        if result.is_ok() {
            debug!("{:?}", result.unwrap());
            info!(
                "Uploaded successfully {} to {}",
                object_name, self.bucket_name
            );
        } else {
            debug!("{:?}", result.unwrap_err());
            error!("Upload of {} to {} failed.", object_name, self.bucket_name);
        }
    }

    #[allow(dead_code)]
    /// Get an object in Vec<u8> form.
    pub async fn get(&self, object_name: &str) -> Option<Vec<u8>> {
        let get_request = self
            .client
            .get_object()
            .bucket(&self.bucket_name)
            .key(object_name)
            .send()
            .await;

        if get_request.is_ok() {
            let result = get_request.unwrap();
            debug!("{:?}", result);
            info!("Got successfully {} from {}", object_name, self.bucket_name);
            let bytes = result.body.collect().await.unwrap().into_bytes().to_vec();
            Some(bytes)
        } else {
            debug!("{:?}", get_request.unwrap_err());
            error!("Unable to get {} from {}.", object_name, self.bucket_name);
            None
        }
    }

    #[allow(dead_code)]
    /// Delete an object.
    pub async fn delete(&self, object_name: &str) {
        let delete_request = self
            .client
            .delete_object()
            .bucket(&self.bucket_name)
            .key(object_name);

        let result = delete_request.send().await;

        if result.is_ok() {
            debug!("{:?}", result.unwrap());
            info!(
                "Deleted successfully {} from {}",
                object_name, self.bucket_name
            );
        } else {
            debug!("{:?}", result.unwrap_err());
            error!(
                "Deletion of {} from {} failed.",
                object_name, self.bucket_name
            );
        }
    }
}
