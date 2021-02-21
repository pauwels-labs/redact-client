use async_trait::async_trait;
use mobc::{Connection, Pool};
use mobc_redis::{redis, RedisConnectionManager};
use std::time::Duration;
use thiserror::Error;
use mobc_redis::redis::{RedisError, AsyncCommands};
use std::sync::Arc;
use std::ops::Deref;
use std::ops::DerefMut;
use crate::storage::Data;
use crate::redis_service;
use crate::redis_service::{RedisServiceError, RedisService};

#[async_trait]
pub trait FetchCacher: Clone + Send + Sync {
    async fn set(&mut self, fetch_id: &str, page_number: i64, value: &Vec<Data>, ttl_seconds: usize) -> Result<(), RedisClientError>;
    async fn get_index(&self, key: &str, index: i64) -> Result<Data, RedisClientError>;
    async fn exists_index(&self, key: &str, index: i64) -> Result<bool, RedisClientError>;
    fn get_collection_size(&self) -> u8;
}

#[derive(Clone)]
pub struct FetchCache<T: redis_service::RedisServicer> {
    redis_service: T,
    collection_page_size: u8,
}

#[derive(Error, Debug)]
pub enum RedisClientError {
    #[error("Failed to connect to Redis")]
    ConnectionError { source: RedisServiceError },

    #[error("Failed to get a redis_service connection from the connection pool")]
    RedisPoolError { source: mobc::Error<RedisServiceError> },

    #[error("Failed to serialize collection")]
    SerializationError { source: serde_json::Error },

    #[error("Failed to deserialize collection")]
    DeserializationError { source: serde_json::Error },

    #[error("Item not found")]
    ItemNotFound { },
}

impl FetchCache<RedisService> {
    pub fn new(connection_string: &str, collection_page_size: u8) -> Result<FetchCache<RedisService>, RedisClientError> {
        let redis_service  = redis_service::RedisService::new(&connection_string).map_err(|source| RedisClientError::ConnectionError { source })?;
        Ok(FetchCache { redis_service, collection_page_size })
    }
}

#[async_trait]
impl<T: redis_service::RedisServicer> FetchCacher for FetchCache<T> {
    async fn set(&mut self, fetch_id: &str, page_number: i64, value: &Vec<Data>, ttl_seconds: usize) -> Result<(), RedisClientError> {
        let serialized_collection = serde_json::to_string(value).map_err(|source| RedisClientError::SerializationError { source })?;
        let cache_key =  format!("fetch_id::{}::start_index::{}", fetch_id, page_number*i64::from(self.collection_page_size));

        self.redis_service.set(&cache_key, &serialized_collection).await.map_err(|source| RedisClientError::ConnectionError { source })?;
        if ttl_seconds > 0 {
            self.redis_service.expire(&cache_key, ttl_seconds).await.map_err(|source| RedisClientError::ConnectionError { source })?;
        }
        Ok(())
    }

    async fn get_index(&self, fetch_id: &str, index: i64) -> Result<Data, RedisClientError> {
        let start_index = index / i64::from(self.collection_page_size);
        let cache_key =  format!("fetch_id::{}::start_index::{}", fetch_id, start_index);

        let string_collection: String = self.redis_service.get(&cache_key).await.map_err(|source| RedisClientError::ConnectionError { source })?;
        let page: Vec<Data> = serde_json::from_str(&string_collection).map_err(|source| RedisClientError::DeserializationError { source })?;

        let result_index = (index % i64::from(self.collection_page_size)) as usize;
        match result_index >= page.len() {
            true => Err(RedisClientError::ItemNotFound {}),
            false => Ok(page[result_index].clone())
        }

    }

    async fn exists_index(&self, fetch_id: &str, index: i64) -> Result<bool, RedisClientError> {
        let start_index = index / i64::from(self.collection_page_size);
        let key =  format!("fetch_id::{}::start_index::{}", fetch_id, start_index);
        self.redis_service.exists(&key).await.map_err(|source| RedisClientError::ConnectionError { source })
    }

    fn get_collection_size(&self) -> u8 {
        return self.collection_page_size;
    }
}

// #[async_trait]
// impl<U> FetchCacher for Arc<U>
//     where
//         U: FetchCacher,
// {
//     async fn set(
//         &mut self,
//         fetch_id: &str,
//         page_number: i64,
//         value: &Vec<Data>,
//         ttl_seconds: usize
//     ) -> Result<(), RedisClientError> {
//         self.deref_mut().set(fetch_id, page_number, value, ttl_seconds).await
//     }
//
//     async fn get_index(&self, key: &str, index: i64) -> Result<Data, RedisClientError> {
//         self.deref().get_index(key, index).await
//     }
//
//     async fn exists_index(&self, key: &str, index: i64) -> Result<bool, RedisClientError> {
//         self.deref().exists_index(key, index).await
//     }
//
//     fn get_collection_size(&self) -> u8 {
//         self.deref().get_collection_size()
//     }
// }

#[cfg(test)]
pub mod tests {
    use super::{RedisClient, FetchCacher, RedisClientError};
    use crate::storage::Data;
    use async_trait::async_trait;
    use mockall::predicate::*;
    use mockall::*;
    use mobc_redis::RedisConnectionManager;
    use mobc::{Connection, Pool, Manager};
    use redis::{AsyncCommands, RedisFuture, FromRedisValue, ToRedisArgs};

    mock! {
        pub FetchCacher {}
        impl Clone for FetchCacher {
            fn clone(&self) -> Self;
        }

        #[async_trait]
        impl FetchCacher for FetchCacher {
            async fn set(&self, fetch_id: &str, page_number: i64, value: &Vec<Data>, ttl_seconds: usize) -> Result<(), RedisClientError>;
            async fn get_index(&self, key: &str, index: i64) -> Result<Data, RedisClientError>;
            async fn exists_index(&self, key: &str, index: i64) -> Result<bool, RedisClientError>;
            fn get_collection_size(&self) -> u8;
        }
    }
}
