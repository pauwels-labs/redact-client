use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use warp::{
    reject::{self, Reject},
    Rejection,
};

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Failed to fetch data")]
    FetchError { source: reqwest::Error },

    #[error("Failed to create data")]
    CreateError { source: reqwest::Error },

    #[error("Failed to deserialize data")]
    DeserializationError { source: reqwest::Error },
}

impl Reject for StorageError {}

#[derive(Serialize, Deserialize, Debug)]
pub struct Data {
    pub data_type: String,
    pub path: String,
    pub value: Value,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DataCollection {
    pub results: Vec<Value>
}

#[async_trait]
pub trait Storer: Clone + Send + Sync {
    async fn get(&self, path: &str) -> Result<Data, Rejection>;
    async fn get_collection(&self, path: &str, skip: i64, page_size: i64) -> Result<DataCollection, Rejection>;
    async fn create(&self, path: &str, value: Data) -> Result<bool, Rejection>;
}

#[derive(Clone)]
pub struct RedactStorer {
    url: String,
}

impl RedactStorer {
    pub fn new(url: &str) -> RedactStorer {
        RedactStorer {
            url: url.to_string(),
        }
    }
}

#[async_trait]
impl Storer for RedactStorer {
    async fn get(&self, path: &str) -> Result<Data, Rejection> {
        match reqwest::get(&format!("{}/data/{}", self.url, path)).await {
            Ok(r) => Ok(r
                .json::<Data>()
                .await
                .map_err(|source| reject::custom(StorageError::DeserializationError { source }))?),
            Err(source) => Err(reject::custom(StorageError::FetchError { source })),
        }
    }

    async fn get_collection(&self, path: &str, skip: i64, page_size: i64) -> Result<DataCollection, Rejection> {
        match reqwest::get(&format!("{}/data/{}?skip={}&page_size={}", self.url, path, skip, page_size)).await {
            Ok(r) => {
                Ok(r
                .json::<DataCollection>()
                .await
                .map_err(|source| reject::custom(StorageError::DeserializationError { source }))?)
            },
            Err(source) => {
                Err(reject::custom(StorageError::FetchError { source }))
            },
        }
    }

    async fn create(&self, path: &str, value: Data) -> Result<bool, Rejection> {
        match reqwest::Client::new()
            .post(&format!("{}/data?path={}", self.url, path))
            .json(&value)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(source) => Err(reject::custom(StorageError::CreateError { source })),
        }
    }
}
