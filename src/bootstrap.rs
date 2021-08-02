use bson::Document;
use std::{convert::TryInto, error::Error};

use redact_config::Configurator;
use redact_crypto::{
    Builder, CryptoError, Entry, HasBuilder, HasByteSource, HasIndex, SourceError, State, Storer,
    TypeBuilderContainer,
};

use crate::error::ClientError;

pub async fn setup_entry<
    Z: HasIndex<Index = Document> + HasBuilder + HasByteSource + 'static,
    T: Configurator,
    S: Storer,
>(
    config: &T,
    config_path: &str,
    storer: &S,
) -> Result<Z, ClientError> {
    let entry = config
        .get::<Entry>(config_path)
        .map_err(|e| ClientError::ConfigError { source: e })?;
    match storer.resolve::<Z>(&entry.value).await {
        Ok(sak) => Ok(sak),
        Err(e) => match e {
            CryptoError::NotFound { .. } => match entry.value {
                State::Referenced { .. } => Err(ClientError::CryptoError { source: e }),
                State::Unsealed { builder, mut bytes } => {
                    let sakb: <Z as HasBuilder>::Builder = TypeBuilderContainer(builder)
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
                    let s = State::Unsealed { builder, bytes };
                    storer
                        .create(entry.path, s)
                        .await
                        .map_err(|e| ClientError::CryptoError { source: e })?;
                    Ok(sak)
                }
                State::Sealed {
                    builder,
                    unsealable,
                } => {
                    let sakb: <Z as HasBuilder>::Builder = TypeBuilderContainer(builder)
                        .try_into()
                        .map_err(|e| ClientError::CryptoError { source: e })?;
                }
            },
            _ => Err(ClientError::CryptoError { source: e }),
        },
    }
}
