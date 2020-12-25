use rand::{prelude::*, thread_rng};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
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

pub fn generate_token() -> Result<String, TokenGenerationError> {
    // Fetch current UNIX timestamp in nanoseconds
    let now = SystemTime::now();
    let ts_nanos = match now.duration_since(UNIX_EPOCH) {
        Ok(d) => Ok(d.as_nanos()),
        Err(source) => Err(TokenGenerationError::SystemTimeError { source }),
    }?;

    // Generate 32 cryptographically secure random bytes
    let mut rng = thread_rng();
    let mut random_bytes: [u8; 32] = [0; 32];
    rng.try_fill_bytes(&mut random_bytes)
        .map_err(|source| TokenGenerationError::RandError { source })?;

    // Hash timestamp and random number together to create a single 32-byte token
    let mut hasher = Sha256::new();
    hasher.update(format!("{}", ts_nanos));
    for b in &random_bytes {
        hasher.update(format!("{}", b));
    }

    Ok(format!("{:X}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn foo() {
        assert_eq!(2 + 2, 4);
    }
}
