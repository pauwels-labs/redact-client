pub mod error;
pub(crate) mod proxy;
pub mod secure;
pub mod unsecure;

use std::sync::Arc;

use crate::{render::Renderer, token::TokenGenerator};

use self::error::QueryParamValidationRejection;
pub use error::{
    BadRequestRejection, CryptoErrorRejection, DataNotFoundRejection,
    IframeTokensDoNotMatchRejection, SerializationRejection, SessionTokenNotFoundRejection,
};
use percent_encoding::percent_decode_str;
use redact_crypto::Storer;
use regex::Regex;
use serde::de::DeserializeOwned;
use warp::{Filter, Rejection, Reply};

pub fn secure<H: Storer, R: Renderer, T: TokenGenerator>(
    storer: Arc<H>,
    render_engine: R,
    token_generator: T,
) -> impl Filter<Extract = (impl Reply, String, Option<String>, Option<String>), Error = Rejection> + Clone
{
    warp::path!("secure" / ..).and(secure::data(storer, render_engine, token_generator))
}

pub fn unsecure<R: Renderer, T: TokenGenerator>(
    token_generator: T,
    render_engine: R,
) -> impl Filter<Extract = (impl Reply, String, String), Error = Rejection> + Clone {
    warp::path!("unsecure" / ..).and(unsecure::data(token_generator, render_engine))
}

pub trait Validate {
    fn validate(&self) -> Result<(), Rejection>;
}

pub fn validate_base64_query_param(str: Option<String>) -> Result<(), Rejection> {
    match str {
        Some(msg) => percent_decode_str(&msg)
            .decode_utf8()
            .map_err(|_| warp::reject::custom(QueryParamValidationRejection))
            .and_then(|str| {
                let base64_regex = Regex::new(r"^[A-Za-z0-9+/]+={0,2}$").unwrap();
                match base64_regex.is_match(&str.to_string()) {
                    true => Ok::<_, Rejection>(()),
                    false => Err(warp::reject::custom(QueryParamValidationRejection)),
                }
            }),
        None => Ok(()),
    }
}

pub fn validated_query_params<T: 'static + DeserializeOwned + Send + Validate>(
) -> impl Filter<Extract = (T,), Error = Rejection> + Copy {
    warp::query::<T>().and_then(move |param: T| async move {
        param.validate()?;
        Ok::<_, Rejection>(param)
    })
}
