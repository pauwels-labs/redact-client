use crate::crypto::SymmetricKeyEncryptDecryptor;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::ops::Deref;
use std::sync::Arc;
use std::vec::Vec;
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
pub enum KeySourceType {
    Value,
    FS,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FsKeyInfo {
    pub is_symmetric: bool,
    pub alg: String,
    pub encrypted_by: Option<String>,
    pub path: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ValueKeyInfo {
    pub is_symmetric: bool,
    pub alg: String,
    pub encrypted_by: Option<String>,
    pub value: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Key<T> {
    pub source: KeySourceType,
    pub name: String,
    pub key_info: T,
}

#[async_trait]
pub trait SymmetricKeyStorer: Clone + Send + Sync {
    async fn get(&self, path: &str) -> Result<Box<dyn SymmetricKeyEncryptDecryptor>, Rejection>;
}

#[derive(Clone)]
pub struct RedactSymmetricKeyStorer {
    url: String,
}

impl RedactSymmetricKeyStorer {
    pub fn new(url: &str) -> RedactSymmetricKeyStorer {
        RedactSymmetricKeyStorer {
            url: url.to_string(),
        }
    }
}

impl SymmetricKeyStorer for RedactSymmetricKeyStorer {
    async fn get(&self, path: &str) -> Result<Box<dyn SymmetricKeyEncryptDecryptor>, Rejection> {
        match reqwest::get(&format!("{}/keys/{}", self.url, path)).await {
            Ok(r) => Ok(r
                .json::<Data>()
                .await
                .map_err(|source| reject::custom(StorageError::DeserializationError { source }))?),
            Err(source) => Err(reject::custom(StorageError::FetchError { source })),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Data {
    pub data_type: String,
    pub path: String,
    pub value: Value,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DataCollection {
    pub results: Vec<Data>,
}

#[async_trait]
pub trait DataStorer: Clone + Send + Sync {
    async fn get(&self, path: &str) -> Result<Data, Rejection>;
    async fn get_collection(
        &self,
        path: &str,
        skip: i64,
        page_size: i64,
    ) -> Result<DataCollection, Rejection>;
    async fn create(&self, path: &str, value: Data) -> Result<bool, Rejection>;
}

#[async_trait]
impl<U> DataStorer for Arc<U>
where
    U: DataStorer,
{
    async fn get(&self, path: &str) -> Result<Data, Rejection> {
        self.deref().get(path).await
    }

    async fn get_collection(
        &self,
        path: &str,
        skip: i64,
        page_size: i64,
    ) -> Result<DataCollection, Rejection> {
        self.deref().get_collection(path, skip, page_size).await
    }

    async fn create(&self, path: &str, value: Data) -> Result<bool, Rejection> {
        self.deref().create(path, value).await
    }
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
impl DataStorer for RedactStorer {
    async fn get(&self, path: &str) -> Result<Data, Rejection> {
        match reqwest::get(&format!("{}/data/{}", self.url, path)).await {
            Ok(r) => Ok(r
                .json::<Data>()
                .await
                .map_err(|source| reject::custom(StorageError::DeserializationError { source }))?),
            Err(source) => Err(reject::custom(StorageError::FetchError { source })),
        }
    }

    async fn get_collection(
        &self,
        path: &str,
        skip: i64,
        page_size: i64,
    ) -> Result<DataCollection, Rejection> {
        match reqwest::get(&format!(
            "{}/data/{}?skip={}&page_size={}",
            self.url, path, skip, page_size
        ))
        .await
        {
            Ok(r) => Ok(r
                .json::<DataCollection>()
                .await
                .map_err(|source| reject::custom(StorageError::DeserializationError { source }))?),
            Err(source) => Err(reject::custom(StorageError::FetchError { source })),
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

#[cfg(test)]
pub mod tests {
    use super::{Data, DataCollection, DataStorer};
    use async_trait::async_trait;
    use mockall::predicate::*;
    use mockall::*;
    use warp::Rejection;

    mock! {
    pub Storer {}
    impl Clone for Storer {
            fn clone(&self) -> Self;
    }
    #[async_trait]
    impl DataStorer for Storer {
    async fn get(&self, path: &str) -> Result<Data, Rejection>;
    async fn get_collection(
            &self,
            path: &str,
            skip: i64,
            page_size: i64,
    ) -> Result<DataCollection, Rejection>;
    async fn create(&self, path: &str, value: Data) -> Result<bool, Rejection>;
    }
    }
}
