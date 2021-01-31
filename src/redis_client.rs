use async_trait::async_trait;
use mobc::{Connection, Pool};
use ::redis::FromRedisValue;
use mobc_redis::{redis, RedisConnectionManager};
use std::time::Duration;
use thiserror::Error;
use mobc_redis::redis::{RedisError, AsyncCommands, RedisResult};
use serde_json::Value;
use std::str::from_utf8;
use crate::storage::Data;

pub type MobcPool = Pool<RedisConnectionManager>;
pub type MobcCon = Connection<RedisConnectionManager>;

const CACHE_POOL_MAX_OPEN: u64 = 16;
const CACHE_POOL_MAX_IDLE: u64 = 8;
const CACHE_POOL_TIMEOUT_SECONDS: u64 = 1;
const CACHE_POOL_EXPIRE_SECONDS: u64 = 60;

#[async_trait]
pub trait FetchCache: Clone + Send + Sync {
    async fn set(&self, fetch_id: &str, index: i64, value: &Vec<Data>, ttl_seconds: usize) -> Result<(), RedisClientError>;
    async fn get_index(&self, key: &str, index: i64) -> Result<Data, RedisClientError>;
    async fn exists_index(&self, key: &str, index: i64) -> Result<bool, RedisClientError>;
}

#[derive(Clone)]
pub struct RedisClient {
    pool: MobcPool,
    collection_page_size: i64
}

#[derive(Error, Debug)]
pub enum RedisClientError {
    #[error("Failed to fetch data")]
    ConnectionError { source: mobc_redis::redis::RedisError },

    #[error("Failed to fetch data")]
    ConnectionError2 { source: ::redis::RedisError },

    #[error("Failed to fetch data")]
    ConnectionError3 { source: mobc::Error<RedisError> },
}


impl RedisClient {
    pub fn new(connection_string: &str, collection_page_size: i64) -> RedisClient {
        let client = redis::Client::open(connection_string).map_err(|source| RedisClientError::ConnectionError { source }).unwrap();
        let manager = RedisConnectionManager::new(client);
        let pool = Pool::builder()
            .get_timeout(Some(Duration::from_secs(CACHE_POOL_TIMEOUT_SECONDS)))
            .max_open(CACHE_POOL_MAX_OPEN)
            .max_idle(CACHE_POOL_MAX_IDLE)
            .max_lifetime(Some(Duration::from_secs(CACHE_POOL_EXPIRE_SECONDS)))
            .build(manager);
        RedisClient { pool, collection_page_size }
    }

    async fn get_con(pool: &MobcPool) -> Result<MobcCon, RedisClientError> {
        pool.get().await.map_err(|source| {
            eprintln!("error connecting to redis: {}", source);
            RedisClientError::ConnectionError3 { source }
        })
    }
}

#[async_trait]
impl FetchCache for RedisClient {
    async fn set(&self, fetch_id: &str, start_index: i64, value: &Vec<Data>, ttl_seconds: usize) -> Result<(), RedisClientError> {
        // TODO: if start_index%PAGE_SIZE != 0 return error
        let serialized_collection = serde_json::to_string(value).unwrap();
        let cache_key =  format!("fetch_id::{}::start_index::{}", fetch_id, start_index);
        println!("{}", cache_key);

        let mut con = RedisClient::get_con(&self.pool).await?;
        con.set(&cache_key, serialized_collection).await.map_err(|source| RedisClientError::ConnectionError { source })?;
        if ttl_seconds > 0 {
            con.expire(&cache_key, ttl_seconds).await.map_err(|source| RedisClientError::ConnectionError { source })?;
        }
        Ok(())
    }

    async fn get_index(&self, fetch_id: &str, index: i64) -> Result<Data, RedisClientError> {
        let start_index = index / self.collection_page_size;
        let cache_key =  format!("fetch_id::{}::start_index::{}", fetch_id, start_index);

        let mut con = RedisClient::get_con(&self.pool).await?;
        let string_collection: String = con.get(&cache_key).await.map_err(|source| RedisClientError::ConnectionError { source })?;
        let page: Vec<Data> = serde_json::from_str(&string_collection).unwrap();

        let result_index = index % self.collection_page_size;
        let data: Data = page[result_index as usize].clone();
        Ok(data)
    }

    async fn exists_index(&self, fetch_id: &str, index: i64) -> Result<bool, RedisClientError> {
        let start_index = index / self.collection_page_size;
        let key =  format!("fetch_id::{}::start_index::{}", fetch_id, start_index);
        let mut con = RedisClient::get_con(&self.pool).await?;
        con.exists(key).await.map_err(|source| RedisClientError::ConnectionError { source })
    }
}

