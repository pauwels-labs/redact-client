use async_trait::async_trait;
use mobc::{Connection, Pool};
use ::redis::FromRedisValue;
use mobc_redis::{redis, RedisConnectionManager};
use std::time::Duration;
use thiserror::Error;
use mobc_redis::redis::{RedisError, AsyncCommands};

pub type MobcPool = Pool<RedisConnectionManager>;
pub type MobcCon = Connection<RedisConnectionManager>;

const CACHE_POOL_MAX_OPEN: u64 = 16;
const CACHE_POOL_MAX_IDLE: u64 = 8;
const CACHE_POOL_TIMEOUT_SECONDS: u64 = 1;
const CACHE_POOL_EXPIRE_SECONDS: u64 = 60;


#[async_trait]
pub trait RedisClientTrait: Clone + Send + Sync {
    async fn set_str(&self, key: &str, value: &str, ttl_seconds: usize) -> Result<(), RedisClientError>;
    async fn get_str(&self, key: &str) -> Result<String, RedisClientError>;
}

#[derive(Clone)]
pub struct RedisClient {
    pool: MobcPool
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
    pub fn new(connection_string: &str) -> RedisClient {
        let client = redis::Client::open(connection_string).map_err(|source| RedisClientError::ConnectionError { source }).unwrap();
        let manager = RedisConnectionManager::new(client);
        let pool = Pool::builder()
            .get_timeout(Some(Duration::from_secs(CACHE_POOL_TIMEOUT_SECONDS)))
            .max_open(CACHE_POOL_MAX_OPEN)
            .max_idle(CACHE_POOL_MAX_IDLE)
            .max_lifetime(Some(Duration::from_secs(CACHE_POOL_EXPIRE_SECONDS)))
            .build(manager);
        RedisClient { pool }
    }

    async fn get_con(pool: &MobcPool) -> Result<MobcCon, RedisClientError> {
        pool.get().await.map_err(|source| {
            eprintln!("error connecting to redis: {}", source);
            RedisClientError::ConnectionError3 { source }
        })
    }
}


#[async_trait]
impl RedisClientTrait for RedisClient {
    async fn set_str(&self, key: &str, value: &str, ttl_seconds: usize) -> Result<(), RedisClientError> {
        let mut con = RedisClient::get_con(&self.pool).await?;
        con.set(key, value).await.map_err(|source| RedisClientError::ConnectionError { source })?;
        if ttl_seconds > 0 {
            con.expire(key, ttl_seconds).await.map_err(|source| RedisClientError::ConnectionError { source })?;
        }
        Ok(())
    }

    async fn get_str(&self, key: &str) -> Result<String, RedisClientError> {
        let mut con = RedisClient::get_con(&self.pool).await?;
        con.get(key).await.map_err(|source| RedisClientError::ConnectionError { source })
    }
}
