use warp::reject::Reject;
use http::StatusCode;
use std::sync::Arc;
use std::ops::Deref;
use std::fs::File;
use std::io::Read;
use std::collections::HashMap;
use thiserror::Error;
use async_trait::async_trait;
use reqwest::Response;

#[derive(Error, Debug)]
pub enum RelayError {
    #[error("Failure happened during relay")]
    RelayRequestError { source: reqwest::Error }
}

impl Reject for RelayError {}

#[async_trait]
pub trait Relayer: Clone + Send + Sync {
    async fn relay(&self, path: String, relay_url: String) -> Result<StatusCode, RelayError>;
    async fn get(&self, relay_url: String) -> Result<Response, RelayError>;
}

#[async_trait]
impl<U> Relayer for Arc<U>
    where
        U: Relayer,
{
    async fn relay(&self, path: String, relay_url: String) -> Result<StatusCode, RelayError> {
        self.deref().relay(path, relay_url).await
    }

    async fn get(&self, relay_url: String) -> Result<Response, RelayError> {
        self.deref().get(relay_url).await
    }
}

#[derive(Debug, Clone)]
pub struct MutualTLSRelayer {
    pub client: reqwest::Client,
}

impl MutualTLSRelayer {
    pub fn new(
        pem_file_path: String,
    ) -> Result<MutualTLSRelayer, RelayError> {
        let mut buf = Vec::new();
        File::open(pem_file_path)
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();
        let pkcs12 = reqwest::Identity::from_pem(&buf).unwrap();

        let client = reqwest::Client::builder()
            .identity(pkcs12)
            .use_rustls_tls()
            .build()
            .unwrap();

        Ok(MutualTLSRelayer { client })
    }
}

#[async_trait]
impl Relayer for MutualTLSRelayer {
    async fn relay(&self, path: String, relay_url: String) -> Result<StatusCode, RelayError> {
        let mut req_body = HashMap::new();
        req_body.insert("path", path);
        req_body.insert("userId", "abc".to_owned());

        self.client
            .post(relay_url)
            .json(&req_body)
            .send()
            .await
            .and_then(|response| response.error_for_status())
            .and_then(|response| Ok(response.status()))
            .map_err(|source| RelayError::RelayRequestError { source })
    }

    async fn get(&self, relay_url: String) -> Result<Response, RelayError> {
        self.client
            .get(relay_url)
            .send()
            .await
            .and_then(|response| response.error_for_status())
            .map_err(|source| RelayError::RelayRequestError { source })
    }
}