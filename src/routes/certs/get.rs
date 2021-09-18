use serde::{Deserialize, Serialize};
use warp::{Filter, Rejection, Reply};
use redact_crypto::{Signer, HasPublicKey, VectorByteSource, ByteSource, PublicAsymmetricKey, Entry, ToEntry, Storer, CryptoError};
use std::sync::Arc;
use redact_crypto::key::SigningKey;
use crate::routes::{CryptoErrorRejection, SerializationRejection};

#[derive(Deserialize, Serialize, Debug)]
struct GetCSRResponseParams {
    csr_params: CSRParams,
    signature: String
}

#[derive(Deserialize, Serialize, Debug)]
struct CSRParams {
    ou: String,
    cn: String,
    subject_key: Entry<PublicAsymmetricKey>
}

/// Creates a Warp filter which generates a "CSR" on GET request
/// CSR parameters are pulled from config and key, and then signed
pub fn csr <T: Storer> (
    ou: String,
    cn: String,
    storer: Arc<T>,
    key_path: String
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::any()
        .and(warp::path!("certs" / "csr"))
        .and(warp::any().map(move || ou.clone()))
        .and(warp::any().map(move || cn.clone()))
        .and(warp::any().map(move || storer.clone()))
        .and(warp::any().map(move || key_path.clone()))
        .and_then(move |ou: String, cn: String, storer: Arc<T>, key_path: String| async move {
            let signing_key_entry = storer.get::<SigningKey>(&key_path)
                .await
                .map_err(CryptoErrorRejection)?;
            let signing_key = signing_key_entry
                .take_resolve()
                .await
                .map_err(CryptoErrorRejection)?;
            let signing_public_key = signing_key
                .public_key()
                .map_err(CryptoErrorRejection)?;
            // Create a new entry with the public key for serialization
            let public_key_entry: Entry<PublicAsymmetricKey> = signing_public_key
                .to_unsealed_entry("path".to_string())
                .map_err(CryptoErrorRejection)?;

            let csr_params = CSRParams {
                ou: ou.to_owned(),
                cn: cn.to_owned(),
                subject_key: public_key_entry
            };

            // Serializing the CSRParams to array of bytes so it can be signed by the client
            let csr_params_string = serde_json::to_string(&csr_params)
                .map_err(SerializationRejection)?;
            let csr_params_bytes = csr_params_string.as_bytes();

            // Generating the signature
            let signature_byte_source = signing_key.sign(
                ByteSource::Vector(
                    VectorByteSource::new(
                        Some(csr_params_bytes)
                    )
                ))
                .map_err(CryptoErrorRejection)?;
            let signature = signature_byte_source
                .get()
                .map_err(|e| {
                    CryptoErrorRejection(CryptoError::InternalError{ source: Box::new(e) })
                })?;

            let response_body = GetCSRResponseParams {
                csr_params,
                signature: base64::encode(signature.to_vec())
            };

            Ok::<_, Rejection>(warp::reply::with_status(
                warp::reply::json(&response_body),
                warp::http::StatusCode::OK,
            ))
            },
        )
}

#[cfg(test)]
mod tests {
    mod csr {
        use crate::routes::certs::get;
        use mockall::predicate::*;
        use mockall::*;
        use redact_crypto::{key::sodiumoxide::{
            SodiumOxideCurve25519PublicAsymmetricKey,
        }, ByteSource, CryptoError, Signer, HasPublicKey, HasByteSource, HasAlgorithmIdentifier, VectorByteSource, TypeBuilder, KeyBuilder, AsymmetricKeyBuilder, SecretAsymmetricKeyBuilder, Entry, State, PublicAsymmetricKey, PublicAsymmetricKeyBuilder};
        use spki::AlgorithmIdentifier;
        use std::sync::Arc;
        use crate::routes::certs::get::GetCSRResponseParams;
        use std::str::from_utf8;
        use redact_crypto::key::sodiumoxide::{SodiumOxideEd25519SecretAsymmetricKeyBuilder, SodiumOxideEd25519PublicAsymmetricKeyBuilder};
        use redact_crypto::key::SigningKey;
        use redact_crypto::storage::tests::MockStorer;
        use std::error::Error;
        use std::fmt;

        mock! {
        pub SigningKey {}
            impl Signer for SigningKey {
                fn sign(&self, bytes: ByteSource) -> Result<ByteSource, CryptoError>;
            }

            impl HasPublicKey for SigningKey {
                type PublicKey = SodiumOxideCurve25519PublicAsymmetricKey;

                fn public_key(&self) -> Result<<Self as HasPublicKey>::PublicKey, CryptoError>;
            }

            impl HasByteSource for SigningKey {
                fn byte_source(&self) -> ByteSource;
            }

            impl HasAlgorithmIdentifier for SigningKey {
                fn algorithm_identifier<'a>(&self) -> AlgorithmIdentifier<'a>;
            }

        }

        #[derive(Debug)]
        struct TestError(String);

        impl fmt::Display for TestError {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "There is an error: {}", self.0)
            }
        }

        impl Error for TestError {}

        #[tokio::test]
        async fn csr() {
            // Unfortunately there is no easy way to mock SigningKeys when retrieving them from
            // storage, so a real SodiumOxideEd25519 key is constructed
            let key_path = ".keys.path.test.";
            let public_key_builder  = TypeBuilder::Key(
                KeyBuilder::Asymmetric(
                    AsymmetricKeyBuilder::Public(
                        PublicAsymmetricKeyBuilder::SodiumOxideEd25519(
                            SodiumOxideEd25519PublicAsymmetricKeyBuilder {}
                        ))));
            let public_key_entry: Entry<PublicAsymmetricKey> = Entry::new(
                key_path.to_owned(),
                public_key_builder,
                State::Unsealed {
                    bytes: ByteSource::Vector(VectorByteSource::new(Some(base64::decode("2V1/lw3FYjtBuOR++i0IJtWSJukwLAUuqfzWpEaTvgI=").unwrap().as_slice()))),
                },
            );

            let ou = "test_ou";
            let cn = "test_cn";

            let mut storer = MockStorer::new();
            storer
                .expect_private_get::<SigningKey>()
                .times(1)
                .withf(move |path| path == key_path.to_owned())
                .returning(move |_| {
                    let key_builder = TypeBuilder::Key(
                        KeyBuilder::Asymmetric(
                            AsymmetricKeyBuilder::Secret(
                                SecretAsymmetricKeyBuilder::SodiumOxideEd25519(
                                    SodiumOxideEd25519SecretAsymmetricKeyBuilder {}
                                ))));
                    Ok(Entry::new(
                        key_path.to_owned(),
                        key_builder,
                        State::Unsealed {
                            bytes: ByteSource::Vector(VectorByteSource::new(Some(base64::decode("8WHFlpG0CWbAhiWnr8VyTU1H8ej5pbozUw/ObovXGJLZXX+XDcViO0G45H76LQgm1ZIm6TAsBS6p/NakRpO+Ag==").unwrap().as_slice()))),
                        },
                    ))
                });

            let get_csr_filter = get::csr(
                ou.to_owned(),
                cn.to_owned(),
                Arc::new(storer),
                key_path.to_owned()
            );

            let response = warp::test::request()
                .path("/certs/csr")
                .reply(&get_csr_filter)
                .await;

            let response_body: GetCSRResponseParams = serde_json::from_str(
                from_utf8(response.body()).unwrap()
            ).unwrap();

            assert_eq!(response.status(), 200);
            assert_eq!(response_body.csr_params.ou, ou);
            assert_eq!(response_body.csr_params.cn, cn);

            let resolved_resp_pk_str = serde_json::to_string(response_body.csr_params.subject_key.resolve().await.unwrap()).unwrap();
            let resolved_expected_pk_str = serde_json::to_string(public_key_entry.resolve().await.unwrap()).unwrap();
            assert_eq!(resolved_resp_pk_str, resolved_expected_pk_str);

            //TODO: Verify signature
        }

        #[tokio::test]
        async fn csr_signing_key_invalid() {
            let key_path = ".keys.path.test.";
            let ou = "test_ou";
            let cn = "test_cn";

            let mut storer = MockStorer::new();
            storer
                .expect_private_get::<SigningKey>()
                .times(1)
                .withf(move |path| path == key_path.to_owned())
                .returning(move |_| {
                    let key_builder = TypeBuilder::Key(
                        KeyBuilder::Asymmetric(
                            AsymmetricKeyBuilder::Secret(
                                SecretAsymmetricKeyBuilder::SodiumOxideEd25519(
                                    SodiumOxideEd25519SecretAsymmetricKeyBuilder {}
                                ))));
                    Ok(Entry::new(
                        key_path.to_owned(),
                        key_builder,
                        State::Unsealed {
                            bytes: ByteSource::Vector(VectorByteSource::new(Some(base64::decode("9HeADa0tXiInhm1qmPeITNk54SUKjp6mZvMU44ieYWw=").unwrap().as_slice()))),
                        },
                    ))
                });

            let get_csr_filter = get::csr(
                ou.to_owned(),
                cn.to_owned(),
                Arc::new(storer),
                key_path.to_owned()
            );

            let response = warp::test::request()
                .path("/certs/csr")
                .reply(&get_csr_filter)
                .await;

            assert_eq!(response.status(), 500);
        }

        #[tokio::test]
        async fn csr_signing_key_not_found() {
            let key_path = ".keys.path.test.";
            let ou = "test_ou";
            let cn = "test_cn";

            let mut storer = MockStorer::new();
            storer
                .expect_private_get::<SigningKey>()
                .times(1)
                .withf(move |path| path == key_path.to_owned())
                .returning(move |_| Err(CryptoError::NotFound { source: Box::new(TestError("bsd".to_owned())) }));

            let get_csr_filter = get::csr(
                ou.to_owned(),
                cn.to_owned(),
                Arc::new(storer),
                key_path.to_owned()
            );

            let response = warp::test::request()
                .path("/certs/csr")
                .reply(&get_csr_filter)
                .await;

            assert_eq!(response.status(), 500);
        }
    }
}

