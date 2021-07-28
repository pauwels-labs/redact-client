use std::error::Error;
use std::fmt::{self, Display};

/// All errors that the client will encounter
#[derive(Debug)]
pub enum ClientError {
    /// Error happened with the config
    ConfigError { source: redact_config::ConfigError },

    /// Error happened in the crypto lib
    CryptoError { source: redact_crypto::CryptoError },

    /// Error happened when handling a source
    SourceError { source: redact_crypto::SourceError },
}

impl Error for ClientError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            ClientError::ConfigError { ref source } => Some(source),
            ClientError::CryptoError { ref source } => Some(source),
            ClientError::SourceError { ref source } => Some(source),
        }
    }
}

impl Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ClientError::ConfigError { .. } => {
                write!(f, "Error occured when handling config")
            }
            ClientError::CryptoError { .. } => {
                write!(f, "Error occured in crypto library")
            }
            ClientError::SourceError { .. } => {
                write!(f, "Error occured while handling a source")
            }
        }
    }
}
