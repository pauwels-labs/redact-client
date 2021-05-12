use async_trait::async_trait;
use redact_crypto::{
    error::CryptoError,
    keys::{AsymmetricKeys, Keys, KeysCollection, SymmetricKeys},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::convert::TryInto;
use std::sync::Arc;
use std::vec::Vec;
use std::{collections::HashMap, ops::Deref};
use thiserror::Error;
use tokio::sync::RwLock;
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

    #[error("There was an error in the crypto library")]
    CryptoError { source: CryptoError },
}

impl Reject for StorageError {}

#[async_trait]
pub trait KeysStorer: Clone + Send + Sync {
    async fn get(&self, path: &str) -> Result<Keys, Rejection>;
    async fn list(&self) -> Result<KeysCollection, Rejection>;
    async fn get_sym(&self, name: &str) -> Result<SymmetricKeys, Rejection>;
    async fn get_asym(&self, name: &str) -> Result<AsymmetricKeys, Rejection>;
}

#[derive(Clone)]
pub struct MemoryCachedKeysStorer<T: KeysStorer> {
    storer: T,
    key_cache: Arc<RwLock<HashMap<String, Keys>>>,
}

#[async_trait]
impl<T: KeysStorer> KeysStorer for MemoryCachedKeysStorer<T> {
    async fn get(&self, name: &str) -> Result<Keys, Rejection> {
        if let Some(key) = self.key_cache.read().await.get(name).map(Keys::clone) {
            Ok(key)
        } else {
            match self.storer.get(name).await {
                Ok(key) => {
                    self.key_cache
                        .write()
                        .await
                        .insert(name.to_owned(), key.clone());
                    Ok(key)
                }
                Err(e) => Err(e),
            }
        }
    }

    async fn get_sym(&self, name: &str) -> Result<SymmetricKeys, Rejection> {
        self.storer.get_sym(name).await
    }

    async fn get_asym(&self, name: &str) -> Result<AsymmetricKeys, Rejection> {
        self.storer.get_asym(name).await
    }
}

#[derive(Clone)]
pub struct RedactKeysStorer {
    url: String,
}

impl RedactKeysStorer {
    pub fn new(url: &str) -> RedactKeysStorer {
        RedactKeysStorer {
            url: url.to_string(),
        }
    }
}

#[async_trait]
impl KeysStorer for RedactKeysStorer {
    async fn get(&self, name: &str) -> Result<Keys, Rejection> {
        match reqwest::get(&format!("{}/keys/{}", self.url, name)).await {
            Ok(r) => Ok(r
                .json::<Keys>()
                .await
                .map_err(|source| reject::custom(StorageError::DeserializationError { source }))?),
            Err(source) => Err(reject::custom(StorageError::FetchError { source })),
        }
    }

    async fn list(&self) -> Result<KeysCollection, Rejection> {
        match reqwest::get(&format!("{}/keys", self.url)).await {
            Ok(r) => Ok(r
                .json::<KeysCollection>()
                .await
                .map_err(|source| reject::custom(StorageError::DeserializationError { source }))?),
            Err(source) => Err(reject::custom(StorageError::FetchError { source })),
        }
    }

    async fn get_sym(&self, name: &str) -> Result<SymmetricKeys, Rejection> {
        self.get(name)
            .await?
            .try_into()
            .map_err(|source| reject::custom(StorageError::CryptoError { source }))
    }

    async fn get_asym(&self, name: &str) -> Result<AsymmetricKeys, Rejection> {
        self.get(name)
            .await?
            .try_into()
            .map_err(|source| reject::custom(StorageError::CryptoError { source }))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Data {
    pub data_type: String,
    pub path: String,
    pub value: Value,
    pub encrypted_by: String,
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
