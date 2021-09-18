use redact_crypto::{PublicAsymmetricKey, Entry};
use std::sync::Arc;
use warp::{Filter, Reply, Rejection};
use serde::{Deserialize, Serialize};
use crate::bootstrap::{setup_cert, DistinguishedName};
use chrono::{DateTime, Utc, NaiveDateTime};
use redact_crypto::key::SigningKey;

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

            let r = request.csr_params.subject_key.cast::<PublicAsymmetricKey>().unwrap();
            let subject_key: &PublicAsymmetricKey = r.resolve().await.unwrap();

            // TODO: Verify signature of CSR params

            let signed_cert = setup_cert(
                &*root_signing_key,
                Some(subject_key),
                &issuer_dn,
                Some(&subject_dn),
                DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(61, 0), Utc),
                DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(61, 0), Utc),
                false
                //subject_alternative_names: Option<&[&str]>,
            ).unwrap();
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
            let builder = SigningKeyBuilder::SodiumOxideEd25519(SodiumOxideEd25519SecretAsymmetricKeyBuilder {});
            let signing_key = builder.build(Some(base64::decode("8WHFlpG0CWbAhiWnr8VyTU1H8ej5pbozUw/ObovXGJLZXX+XDcViO0G45H76LQgm1ZIm6TAsBS6p/NakRpO+Ag==").unwrap().as_slice())).unwrap();

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

            let request_body = GetCSRRequestParams {
                csr_params: CSRParams {
                    ou: "req_ou".to_string(),
                    cn: "req_cn".to_string(),
                    subject_key: public_key_entry
                },
                signature: "sig".to_owned()
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

        // TODO
        // #[tokio::test]
        // async fn csr_signature_verification_failure() { }
    }

}