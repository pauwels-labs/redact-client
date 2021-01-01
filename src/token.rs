use rand::{prelude::*, thread_rng, Rng};
use sha2::{Digest, Sha256};
use std::sync::{Arc, RwLock};
use thiserror::Error;
use warp::{
    reject::{self, Reject},
    Rejection,
};

#[derive(Error, Debug)]
pub enum TokenGenerationError {
    #[error("Failed to retrieve the number of nanoseconds since UNIX epoch")]
    SystemTimeError { source: std::time::SystemTimeError },

    #[error("Failed to generate cryptographically secure random bytes")]
    RandError { source: rand::Error },
}

impl Reject for TokenGenerationError {}

impl std::convert::From<TokenGenerationError> for Rejection {
    fn from(error: TokenGenerationError) -> Self {
        reject::custom(error)
    }
}

pub trait TokenGenerator: Clone + Send + Sync {
    fn generate_token(&mut self) -> Result<String, TokenGenerationError>;
}

pub struct FromCustomRng<T: Rng + Send + Sync> {
    rand_source: Arc<RwLock<T>>,
}

#[derive(Clone)]
pub struct FromThreadRng;

impl<T: Rng + Send + Sync> Clone for FromCustomRng<T> {
    fn clone(&self) -> FromCustomRng<T> {
        FromCustomRng {
            rand_source: self.rand_source.clone(),
        }
    }
}

impl<T: Rng + Send + Sync> TokenGenerator for FromCustomRng<T> {
    fn generate_token(&mut self) -> Result<String, TokenGenerationError> {
        // Generate 32 cryptographically secure random bytes
        let mut random_bytes: [u8; 32] = [0; 32];
        self.rand_source
            .write()
            .unwrap()
            .try_fill_bytes(&mut random_bytes)
            .map_err(|source| TokenGenerationError::RandError { source })?;

        // Hash random bytes to create a displayable 32-byte string
        let mut hasher = Sha256::new();
        for b in &random_bytes {
            hasher.update(format!("{}", b));
        }

        Ok(format!("{:X}", hasher.finalize()))
    }
}

impl TokenGenerator for FromThreadRng {
    fn generate_token(&mut self) -> Result<String, TokenGenerationError> {
        // Generate 32 cryptographically secure random bytes
        let mut random_bytes: [u8; 32] = [0; 32];
        thread_rng()
            .try_fill_bytes(&mut random_bytes)
            .map_err(|source| TokenGenerationError::RandError { source })?;

        // Hash random bytes to create a displayable 32-byte string
        let mut hasher = Sha256::new();
        for b in &random_bytes {
            hasher.update(format!("{}", b));
        }

        Ok(format!("{:X}", hasher.finalize()))
    }
}

impl<T: Rng + Send + Sync> FromCustomRng<T> {
    pub fn new(rand_source: T) -> FromCustomRng<T> {
        FromCustomRng {
            rand_source: Arc::new(RwLock::new(rand_source)),
        }
    }
}

impl FromThreadRng {
    pub fn new() -> FromThreadRng {
        FromThreadRng {}
    }
}

#[cfg(test)]
mod tests {
    use crate::token::{FromCustomRng, TokenGenerator};
    use rand::prelude::*;
    use rand_pcg::Pcg64;

    #[test]
    fn get_token() {
        let mut token_generator = FromCustomRng::new(Pcg64::seed_from_u64(1));
        let token = token_generator.generate_token().unwrap();
        assert_eq!(
            token,
            "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C"
        );
    }
}
