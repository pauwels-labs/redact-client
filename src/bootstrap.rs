use std::convert::TryInto;

use redact_config::Configurator;
use redact_crypto::{
    Algorithm, Builder, CryptoError, Entry, HasBuilder, State, StorableType, Storer,
    TypeBuilderContainer,
};

use crate::error::ClientError;

pub async fn setup_entry<Z: StorableType, T: Configurator, S: Storer>(
    config: &T,
    config_path: &str,
    storer: &S,
) -> Result<Entry<Z>, ClientError> {
    let mut entry = config
        .get::<Entry<Z>>(config_path)
        .map_err(|e| ClientError::ConfigError { source: e })?;
    match entry.resolve().await {
        Ok(_) => Ok(entry),
        Err(e) => match e {
            CryptoError::NotFound { .. } => match entry.value {
                State::Referenced { .. } => Err(ClientError::CryptoError { source: e }),
                State::Unsealed { ref mut bytes } => {
                    let sakb: <Z as HasBuilder>::Builder = TypeBuilderContainer(entry.builder)
                        .try_into()
                        .map_err(|e| ClientError::CryptoError { source: e })?;
                    let sak = sakb
                        .build(None)
                        .map_err(|e| ClientError::CryptoError { source: e })?;
                    bytes
                        .set(
                            sak.byte_source()
                                .get()
                                .map_err(|e| ClientError::SourceError { source: e })?,
                        )
                        .map_err(|e| ClientError::SourceError { source: e })?;
                    Ok(storer
                        .create(entry)
                        .await
                        .map_err(|e| ClientError::CryptoError { source: e })?)
                }
                State::Sealed {
                    ref mut ciphertext,
                    ref algorithm,
                } => {
                    let sakb: <Z as HasBuilder>::Builder = TypeBuilderContainer(entry.builder)
                        .try_into()
                        .map_err(|e| ClientError::CryptoError { source: e })?;
                    let sak = sakb
                        .build(None)
                        .map_err(|e| ClientError::CryptoError { source: e })?;
                    let sak_ciphertext = algorithm
                        .seal(&sak.byte_source())
                        .await
                        .map_err(|e| ClientError::CryptoError { source: e })?;
                    ciphertext
                        .set(
                            sak_ciphertext
                                .get()
                                .map_err(|e| ClientError::SourceError { source: e })?,
                        )
                        .map_err(|e| ClientError::SourceError { source: e })?;
                    Ok(storer
                        .create(entry)
                        .await
                        .map_err(|e| ClientError::CryptoError { source: e })?)
                }
            },
            _ => Err(ClientError::CryptoError { source: e }),
        },
    }
}
