use redact_crypto::{PublicAsymmetricKey, Entry, Verifier, ByteSource, VectorByteSource};
use std::sync::Arc;
use warp::{Filter, Reply, Rejection};
use serde::{Deserialize, Serialize};
use crate::bootstrap::{setup_cert, DistinguishedName};
use chrono::{DateTime, Utc, NaiveDateTime};
use redact_crypto::key::{SigningKey, VerifyingKey};
use crate::routes::{CryptoErrorRejection, BadRequestRejection};
use crate::routes::error::CertificateGenerationRejection;

#[derive(Deserialize, Serialize, Debug)]
struct GetCSRRequestParams {
    csr_params: CSRParams,
    signature: String
}

#[derive(Deserialize, Serialize, Debug)]
struct CSRParams {
    ou: String,
    cn: String,
    subject_key: Entry<PublicAsymmetricKey>,
}

#[derive(Deserialize, Serialize, Debug)]
struct CertResponse {
    cert_bytes: String,
}

pub fn sign_cert(root_signing_key: Arc<SigningKey>, o: String, ou: String, cn: String)
    -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::any()
        .and(warp::path!("certs"))
        .and(warp::filters::body::json::<GetCSRRequestParams>())
        .and(warp::any().map(move || root_signing_key.clone()))
        .and(warp::any().map(move || o.clone()))
        .and(warp::any().map(move || ou.clone()))
        .and(warp::any().map(move || cn.clone()))
        .and_then(move |
            request: GetCSRRequestParams,
            root_signing_key: Arc<SigningKey>,
            o: String,
            ou: String,
            cn: String
        | async move {
            let subject_dn = DistinguishedName {
                o: "abc",
                ou: &request.csr_params.ou,
                cn: &request.csr_params.cn
            };

            let issuer_dn = DistinguishedName {
                o: &o,
                ou: &ou,
                cn: &cn
            };

            let csr_params_string = serde_json::to_string(&request.csr_params)
                .map_err(|_| warp::reject::custom(BadRequestRejection))?;
            let r = request.csr_params.subject_key.cast::<VerifyingKey>()
                .map_err(|_| warp::reject::custom(BadRequestRejection))?;
            let subject_key: &VerifyingKey = r.resolve()
                .await
                .map_err(|_| warp::reject::custom(BadRequestRejection))?;
            let csr_params_bytes = csr_params_string.as_bytes();

            subject_key.verify(
                ByteSource::Vector(
                    VectorByteSource::new(
                        Some(csr_params_bytes)
                    )
                ),
                ByteSource::Vector(
                    VectorByteSource::new(
                        Some(base64::decode(request.signature)
                            .map_err(|_| warp::reject::custom(BadRequestRejection))?
                            .as_ref())
                    )
                )
            ).map_err(CryptoErrorRejection)?;

            let signed_cert = setup_cert(
                &*root_signing_key,
                Some(subject_key),
                &issuer_dn,
                Some(&subject_dn),
                DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(61, 0), Utc),
                DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(61, 0), Utc),
                false
                //subject_alternative_names: Option<&[&str]>,
            ).map_err(CertificateGenerationRejection)?;
            let cert_string = base64::encode(signed_cert);

            Ok::<_, Rejection>(warp::reply::with_status(
                warp::reply::json(&CertResponse { cert_bytes: cert_string } ),
                warp::http::StatusCode::OK,
            ))
        },
        )
}

#[cfg(test)]
mod tests {
    mod certs {
        use redact_crypto::key::SigningKeyBuilder;
        use redact_crypto::key::sodiumoxide::{SodiumOxideEd25519SecretAsymmetricKeyBuilder, SodiumOxideEd25519PublicAsymmetricKeyBuilder};
        use redact_crypto::{Builder, KeyBuilder, PublicAsymmetricKeyBuilder, AsymmetricKeyBuilder, Entry, PublicAsymmetricKey, State, VectorByteSource, ByteSource, TypeBuilder};
        use crate::routes::certs::post;
        use std::sync::Arc;
        use std::str::from_utf8;
        use crate::routes::certs::post::{GetCSRRequestParams, CSRParams, CertResponse};

        #[tokio::test]
        async fn csr() {
            let pk_base64 = "zJK9F0iLkPFGTUW2KBjDDAsitgTTa6qONvjPCFv+KUo=";
            let sk_base64 = "yBLwIZSTRuym90wR3pJ8RSVEwVGCRA6rP5z0ffqvrXbMkr0XSIuQ8UZNRbYoGMMMCyK2BNNrqo42+M8IW/4pSg==";
            let signature_base64 = "BeIvZcXa112A89r3/Lh1SKMstL3gmCHysba4jQ8jRvyxO7/SvElCWlTfF1LHGLtPobd+4Y5pydDQMJxu+s7oCg==";

            let builder = SigningKeyBuilder::SodiumOxideEd25519(SodiumOxideEd25519SecretAsymmetricKeyBuilder {});
            let signing_key = builder.build(
                Some(
                    base64::decode(sk_base64)
                        .unwrap()
                        .as_slice()
                )).unwrap();

            let public_key_builder  = TypeBuilder::Key(
                KeyBuilder::Asymmetric(
                    AsymmetricKeyBuilder::Public(
                        PublicAsymmetricKeyBuilder::SodiumOxideEd25519(
                            SodiumOxideEd25519PublicAsymmetricKeyBuilder {}
                        ))));
            let public_key_entry: Entry<PublicAsymmetricKey> = Entry::new(
                "".to_owned(),
                public_key_builder,
                State::Unsealed {
                    bytes: ByteSource::Vector(
                        VectorByteSource::new(
                            Some(
                                base64::decode(pk_base64)
                                    .unwrap().as_slice()
                            ))),
                },
            );

            let request_body = GetCSRRequestParams {
                csr_params: CSRParams {
                    ou: "req_ou".to_string(),
                    cn: "req_cn".to_string(),
                    subject_key: public_key_entry
                },
                signature: signature_base64.to_owned()
            };

            let o = "test_o";
            let ou = "test_ou";
            let cn = "test_cn";
            let post_csr_filter = post::sign_cert(
                Arc::new(signing_key),
                o.to_owned(),
                ou.to_owned(),
                cn.to_owned(),
            );

            let response = warp::test::request()
                .path("/certs")
                .body(serde_json::to_string(&request_body).unwrap())
                .reply(&post_csr_filter)
                .await;

            let _response_body: CertResponse = serde_json::from_str(
                from_utf8(response.body()).unwrap()
            ).unwrap();

            assert_eq!(response.status(), 200);

            // TODO: verify cert parameters
        }


        #[tokio::test]
        async fn csr_bad_signature() {
            let pk_base64 = "ddTMU+n/8/OGZmzly4d2AKCVXHXJeEYxao8jtvHhwc0=";
            let sk_base64 = "8C6W7FC/PGgqJhupLIlAhhQprxSgHcAi0eFyYFY6YTZ11MxT6f/z84ZmbOXLh3YAoJVcdcl4RjFqjyO28eHBzQ==";
            let signature_base64 = "t9nxBsugclUG3FL6p77tg1XOZk52o5LLUuAwNSy5oLifm4gpYERGwrFaXyT6MEbQ7A/5/SGWmDjNaMpzaNFZDQ==";

            let builder = SigningKeyBuilder::SodiumOxideEd25519(SodiumOxideEd25519SecretAsymmetricKeyBuilder {});
            let signing_key = builder.build(
                Some(
                    base64::decode(sk_base64)
                        .unwrap()
                        .as_slice()
                )).unwrap();

            let public_key_builder  = TypeBuilder::Key(
                KeyBuilder::Asymmetric(
                    AsymmetricKeyBuilder::Public(
                        PublicAsymmetricKeyBuilder::SodiumOxideEd25519(
                            SodiumOxideEd25519PublicAsymmetricKeyBuilder {}
                        ))));
            let public_key_entry: Entry<PublicAsymmetricKey> = Entry::new(
                "".to_owned(),
                public_key_builder,
                State::Unsealed {
                    bytes: ByteSource::Vector(
                        VectorByteSource::new(
                            Some(
                                base64::decode(pk_base64)
                                    .unwrap().as_slice()
                            ))),
                },
            );

            let request_body = GetCSRRequestParams {
                csr_params: CSRParams {
                    ou: "req_ou".to_string(),
                    cn: "req_cn".to_string(),
                    subject_key: public_key_entry
                },
                signature: signature_base64.to_owned()
            };

            let o = "test_o";
            let ou = "test_ou";
            let cn = "test_cn";
            let post_csr_filter = post::sign_cert(
                Arc::new(signing_key),
                o.to_owned(),
                ou.to_owned(),
                cn.to_owned(),
            );

            let response = warp::test::request()
                .path("/certs")
                .body(serde_json::to_string(&request_body).unwrap())
                .reply(&post_csr_filter)
                .await;

            assert_eq!(response.status(), 500);
        }
    }

}