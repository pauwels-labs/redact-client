use std::error::Error;
use std::fmt::{self, Display};

/// All errors that the client will encounter
#[derive(Debug)]
pub enum ClientError {
    /// Represents an error which occurred in some internal system
    InternalError {
        source: Box<dyn Error + Send + Sync>,
    },

    /// Error occurred when trying to verify a domain
    DomainParsingError { kind: addr::error::Kind, input: String },

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
            ClientError::InternalError { ref source } => Some(source.as_ref()),
            ClientError::DomainParsingError { .. } => None,
            ClientError::ConfigError { ref source } => Some(source),
            ClientError::CryptoError { ref source } => Some(source),
            ClientError::SourceError { ref source } => Some(source),
        }
    }
}

impl Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ClientError::InternalError { .. } => {
                write!(f, "Internal error occurred")
            }
            ClientError::DomainParsingError { ref kind, ref input } => {
                write!(f, "Error occurred during domain parsing ({:?}) on input: {}", kind, input)
            }
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
