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

pub async fn get(url: &str, path: String) -> Result<Data, Rejection> {
    match reqwest::get(&format!("{}/data?path={}", url, path)).await {
        Ok(r) => Ok(r
            .json::<Data>()
            .await
            .map_err(|source| reject::custom(StorageError::DeserializationError { source }))?),
        Err(source) => Err(reject::custom(StorageError::FetchError { source })),
    }
}
