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

#[derive(Serialize)]
struct NotFoundResponse {}

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

