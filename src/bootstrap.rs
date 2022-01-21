use crate::{
    error::ClientError,
    render::{HandlebarsRenderer, RenderError},
};
use redact_config::Configurator;
use redact_crypto::{
    Algorithm, Builder, CryptoError, Entry, HasBuilder, State, StorableType, TypeBuilderContainer,
};
use std::{collections::HashMap, convert::TryInto};

pub fn setup_html_render_engine<'reg>() -> Result<HandlebarsRenderer<'reg>, RenderError> {
    let mut template_mapping = HashMap::new();
    template_mapping.insert("unsecure", "./static/unsecure.handlebars");
    template_mapping.insert("secure", "./static/secure.handlebars");
    template_mapping.insert("processing", "./static/processing.handlebars");
    HandlebarsRenderer::new(template_mapping)
}

pub async fn setup_entry<Z: StorableType, T: Configurator>(
    config: &T,
    config_path: &str,
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
                    Ok(entry)
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
                    Ok(entry)
                }
            },
            _ => Err(ClientError::CryptoError { source: e }),
        },
    }
}
