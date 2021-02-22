use async_trait::async_trait;
use mobc::{Connection, Pool};
use mobc_redis::{redis, RedisConnectionManager};
use std::time::Duration;
use thiserror::Error;
use mobc_redis::redis::{RedisError, AsyncCommands};
use std::sync::Arc;
use std::ops::Deref;

pub type MobcPool = Pool<RedisConnectionManager>;
pub type MobcCon = Connection<RedisConnectionManager>;

const CACHE_POOL_MAX_OPEN: u64 = 16;
const CACHE_POOL_MAX_IDLE: u64 = 8;
const CACHE_POOL_TIMEOUT_SECONDS: u64 = 1;
const CACHE_POOL_EXPIRE_SECONDS: u64 = 60;

#[async_trait]
pub trait RedisServicer: Clone + Send + Sync {
    async fn set(&self, key: &str, value: &str) -> Result<(), RedisServiceError>;
    async fn get(&self, key: &str) -> Result<String, RedisServiceError>;
    async fn exists(&self, key: &str) -> Result<bool, RedisServiceError>;
    async fn expire(&self, key: &str, seconds: usize) -> Result<bool, RedisServiceError>;
}

#[derive(Clone)]
pub struct RedisService {
    pool: MobcPool,
}

#[derive(Error, Debug)]
pub enum RedisServiceError {
    #[error("Failed to connect to Redis")]
    ConnectionError { source: mobc_redis::redis::RedisError },

    #[error("Failed to get a redis_service connection from the connection pool")]
    RedisPoolError { source: mobc::Error<RedisError> }
}

impl RedisService {
    pub fn new(connection_string: &str) -> Result<RedisService, RedisServiceError> {
        let client = redis::Client::open(connection_string).map_err(|source| RedisServiceError::ConnectionError { source })?;
        let manager = RedisConnectionManager::new(client);
        let pool = Pool::builder()
            .get_timeout(Some(Duration::from_secs(CACHE_POOL_TIMEOUT_SECONDS)))
            .max_open(CACHE_POOL_MAX_OPEN)
            .max_idle(CACHE_POOL_MAX_IDLE)
            .max_lifetime(Some(Duration::from_secs(CACHE_POOL_EXPIRE_SECONDS)))
            .build(manager);
        Ok(RedisService { pool })
    }

    async fn get_con(pool: &MobcPool) -> Result<MobcCon, RedisServiceError> {
        pool.get().await.map_err(|source| {
            RedisServiceError::RedisPoolError { source }
        })
    }
}

#[async_trait]
impl RedisServicer for RedisService {

    async fn set(&self, key: &str, value: &str) -> Result<(), RedisServiceError> {
        let mut con = RedisService::get_con(&self.pool).await?;
        con.set(key, value).await.map_err(|source| RedisServiceError::ConnectionError { source })
    }

    async fn get(&self, key: &str) -> Result<String, RedisServiceError> {
        let mut con = RedisService::get_con(&self.pool).await?;
        con.get(key).await.map_err(|source| RedisServiceError::ConnectionError { source })
    }

    async fn exists(&self, key: &str) -> Result<bool, RedisServiceError> {
        let mut con = RedisService::get_con(&self.pool).await?;
        con.exists(key).await.map_err(|source| RedisServiceError::ConnectionError { source })
    }

    async fn expire(&self, key: &str, seconds: usize) -> Result<bool, RedisServiceError> {
        let mut con = RedisService::get_con(&self.pool).await?;
        con.expire(key, seconds).await.map_err(|source| RedisServiceError::ConnectionError { source })
    }
}

#[async_trait]
impl<U> RedisServicer for Arc<U>
    where
        U: RedisServicer,
{
    async fn set(&self, key: &str, value: &str) -> Result<(), RedisServiceError> {
        self.deref().set(key, value).await
    }

    async fn get(&self, key: &str) -> Result<String, RedisServiceError> {
        self.deref().get(key).await
    }

    async fn exists(&self, key: &str) -> Result<bool, RedisServiceError> {
        self.deref().exists(key).await
    }

    async fn expire(&self, key: &str, seconds: usize) -> Result<bool, RedisServiceError> {
        self.deref().expire(key, seconds).await
    }
}

#[cfg(test)]
pub mod tests {
    use super::{RedisServicer, RedisServiceError};
    use async_trait::async_trait;
    use mockall::predicate::*;
    use mockall::*;

    mock! {
        pub RedisServicer {}
        impl Clone for RedisServicer {
            fn clone(&self) -> Self;
        }

        #[async_trait]
        impl RedisServicer for RedisServicer {
            async fn set(&self, key: &str, value: &str) -> Result<(), RedisServiceError>;
            async fn get(&self, key: &str) -> Result<String, RedisServiceError>;
            async fn exists(&self, key: &str) -> Result<bool, RedisServiceError>;
            async fn expire(&self, key: &str, seconds: usize) -> Result<bool, RedisServiceError>;
        }
    }
}
