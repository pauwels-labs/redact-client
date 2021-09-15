use serde::{Deserialize, Serialize};
use warp::{Filter, Rejection, Reply};
use redact_crypto::{Signer, HasPublicKey, HasByteSource, HasAlgorithmIdentifier, VectorByteSource, ByteSource};
use std::sync::Arc;

#[derive(Deserialize, Serialize, Debug, Clone)]
struct GetCSRResponseParams {
    csr_params: CSRParams,
    signature: String
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct CSRParams {
    ou: String,
    cn: String,
    subject_key: String,
}

pub fn csr<K: Signer + HasPublicKey + HasByteSource + HasAlgorithmIdentifier + Send + Sync>(
    ou: String,
    cn: String,
    root_signing_key: Arc<K>
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::any()
        .and(warp::path!("certs" / "csr"))
        .and(warp::any().map(move || ou.clone()))
        .and(warp::any().map(move || cn.clone()))
        .and(warp::any().map(move || root_signing_key.clone()))
        .and_then(move |ou: String, cn: String, root_signing_key: Arc<K>| async move {
            let csr_params = CSRParams {
                ou: ou.to_owned(),
                cn: cn.to_owned(),
                subject_key: base64::encode(
                    root_signing_key.byte_source()
                        .get()
                        .map_err(|_| warp::reject())?
                        .to_vec()
                )
            };

            let csr_params_string = serde_json::to_string(&csr_params)
                .map_err(|_| warp::reject())?;
            let csr_params_bytes = csr_params_string.as_bytes();

            let signature_byte_source = root_signing_key.sign(
                ByteSource::Vector(
                    VectorByteSource::new(
                        Some(csr_params_bytes)
                    )
                ))
                .map_err(|_| warp::reject())?;
            let signature = signature_byte_source
                .get()
                .map_err(|_| warp::reject())?;

            let resp = GetCSRResponseParams {
                csr_params,
                signature: base64::encode(signature.to_vec())
            };

            Ok::<_, Rejection>(warp::reply::with_status(
                warp::reply::json(&resp),
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
        }, ByteSource, CryptoError, Signer, HasPublicKey, HasByteSource, HasAlgorithmIdentifier, VectorByteSource};
        use spki::AlgorithmIdentifier;
        use std::sync::Arc;
        use crate::routes::certs::get::{CSRParams, GetCSRResponseParams};
        use std::str::from_utf8;

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



        #[tokio::test]
        async fn csr() {
            let ou = "ou".to_owned();
            let cn = "cn".to_owned();
            let csr_params = CSRParams {
                ou: ou.clone(),
                cn: cn.clone(),
                subject_key: base64::encode("test_subject_key".as_bytes())
            };
            let csr_params_string = serde_json::to_string(&csr_params).unwrap();

            let mut mock_signing_key = MockSigningKey::new();
            mock_signing_key
                .expect_byte_source()
                .times(1)
                .returning(|| {
                    ByteSource::Vector(
                        VectorByteSource::new(
                            Some("test_subject_key".as_bytes())
                        )
                    )
                });
            mock_signing_key
                .expect_sign()
                .times(1)
                .withf(move |byte_source| base64::encode(byte_source.get().unwrap()) ==
                    base64::encode(csr_params_string.as_bytes()))
                .returning(|_byte_source| {
                    Ok(ByteSource::Vector(
                        VectorByteSource::new(
                            Some("test_signature".as_bytes())
                        )
                    ))
                });

            let get_csr_filter = get::csr(
                ou.clone(),
                cn.clone(),
                Arc::new(mock_signing_key)
            );

            let res = warp::test::request()
                .path("/certs/csr")
                .reply(&get_csr_filter)
                .await;

            let resp: GetCSRResponseParams = serde_json::from_str(
                from_utf8(res.body()).unwrap()
            ).unwrap();

            assert_eq!(res.status(), 200);
            assert_eq!(resp.csr_params.ou, ou);
            assert_eq!(resp.csr_params.cn, cn);
            assert_eq!(resp.csr_params.subject_key, base64::encode("test_subject_key".as_bytes()));
            assert_eq!(resp.signature, base64::encode("test_signature".as_bytes()));
        }
    }
}

