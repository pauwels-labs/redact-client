use rand::{thread_rng, Rng};
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
            .try_fill(&mut random_bytes)
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
            .try_fill(&mut random_bytes)
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
    use crate::token::{FromCustomRng, FromThreadRng, TokenGenerationError, TokenGenerator};
    use mockall::predicate::*;
    use mockall::*;
    use rand::{prelude::*, Error, RngCore};
    use rand_pcg::Pcg64;

    mock! {
    FailingRng {}
    impl RngCore for FailingRng {
        fn fill_bytes(&mut self, dest: &mut [u8]);
        fn next_u32(&mut self) -> u32;
        fn next_u64(&mut self) -> u64;
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error>;
    }
    }

    #[test]
    fn test_token_generation_with_deterministic_rng() {
        let mut token_generator = FromCustomRng::new(Pcg64::seed_from_u64(1));
        let token = token_generator.generate_token().unwrap();
        assert_eq!(
            token,
            "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C"
        );
    }

    #[test]
    fn test_token_generation_with_thread_local_rng() {
        let mut token_generator = FromThreadRng::new();
        let token = token_generator.generate_token().unwrap();
        assert_eq!(token.chars().count(), 64);
    }

    #[test]
    #[should_panic(expected = "filling array failed")]
    fn test_token_generation_with_rng_error() {
        let mut failing_rng = MockFailingRng::new();
        let err = Error::new("filling array failed".to_owned());
        failing_rng
            .expect_try_fill_bytes()
            .return_once(move |_| Err(err));
        let mut token_generator = FromCustomRng::new(failing_rng);
        let _ = token_generator.generate_token().unwrap();
    }

    #[test]
    fn test_converting_token_generation_error_to_warp_rejection() {
        let rand_err = Error::new("some random error".to_string());
        let token_generation_error = TokenGenerationError::RandError { source: rand_err };
        let _: warp::Rejection = warp::Rejection::from(token_generation_error);
    }

    #[test]
    fn test_clone_fromcustomrng() {
        let rng = FromCustomRng::new(Pcg64::seed_from_u64(1));
        let _ = rng.clone();
    }
}
