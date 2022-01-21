pub mod get;
pub mod post;

use bytes::buf::BufMut;
use futures::TryStreamExt;
use redact_crypto::{
    BinaryData, BinaryType, CryptoError, Data, Storer, SymmetricKey, ToEntry,
    ToSymmetricByteAlgorithm,
};
use std::{convert::TryFrom, sync::Arc};
use warp::{multipart::FormData, Filter, Rejection, Reply};

use crate::{
    relayer::Relayer,
    render::Renderer,
    routes::{
        error::RelayRejection, validated_query_params, BadRequestRejection, CryptoErrorRejection,
    },
    token::TokenGenerator,
};
use percent_encoding::{percent_decode, percent_decode_str};
use crate::routes::error::QueryParamValidationRejection;

pub fn get<R: Renderer + Clone + Send + 'static, H: Storer, T: TokenGenerator>(
    storer: Arc<H>,
    render_engine: R,
    token_generator: T,
) -> impl Filter<Extract = (Box<dyn Reply>, String, Option<String>, Option<String>), Error = Rejection>
       + Clone {
    warp::get()
        .and(warp::path!(String / String))
        .and(warp::any().map(move || token_generator.clone().generate_token().unwrap()))
        .and(validated_query_params::<get::QueryParams>())
        .and(warp::any().map(move || storer.clone()))
        .and(warp::any().map(move || render_engine.clone()))
        .and_then(
            move |path: String,
                  old_token: String,
                  new_token: String,
                  query: get::QueryParams,
                  storer: Arc<H>,
                  render_engine: R| async move {
                let data_entry = match storer.get::<Data>(&path).await {
                    Ok(e) => Ok(Some(e)),
                    Err(e) => match e {
                        CryptoError::NotFound { .. } => Ok(None),
                        _ => Err(e),
                    },
                }
                .map_err(CryptoErrorRejection)?;

                let data = match data_entry {
                    Some(data_entry) => data_entry
                        .take_resolve()
                        .await
                        .map_err(CryptoErrorRejection)?,
                    None => {
                        if let Some(data_type) = query.data_type.clone() {
                            match data_type.to_ascii_lowercase().as_ref() {
                                "bool" => Data::Bool(false),
                                "u64" => Data::U64(0),
                                "i64" => Data::I64(0),
                                "f64" => Data::F64(0.0),
                                "media" => Data::Binary(None),
                                _ => Data::String("".to_owned()),
                            }
                        } else {
                            Data::String("".to_owned())
                        }
                    }
                };

                let new_path: Option<String> = match query.edit {
                    Some(true) => Some(format!("/secure/data/{}/{}", &path, &new_token)),
                    _ => None,
                };

                Ok::<_, Rejection>((
                    Box::new(get::reply(data, &path, &new_token, query, &render_engine)?)
                        as Box<dyn Reply>,
                    format!("/secure/data/{}/{}", &path, &old_token),
                    new_path,
                    Some(new_token),
                ))
            },
        )
        .untuple_one()
}

pub fn get_raw<H: Storer>(
    storer: Arc<H>,
) -> impl Filter<Extract = (Box<dyn Reply>,), Error = Rejection> + Clone {
    warp::get()
        .and(warp::path!("raw" / String / String))
        .and(warp::any().map(move || storer.clone()))
        .and_then(
            move |path: String,
                  old_token: String,
                  storer: Arc<H>| async move {
                let data_entry = match storer.get::<Data>(&path).await {
                    Ok(e) => Ok(Some(e)),
                    Err(e) => match e {
                        CryptoError::NotFound { .. } => Ok(None),
                        _ => Err(e),
                    },
                }
                    .map_err(CryptoErrorRejection)?;

                let data = match data_entry {
                    Some(data_entry) => data_entry
                        .take_resolve()
                        .await
                        .map_err(CryptoErrorRejection)?,
                    None => {
                        Data::String("".to_owned())
                    }
                };

                Ok::<_, Rejection>(Box::new(warp::reply::with_status(
                    warp::reply::json(&{data}),
                    warp::http::StatusCode::OK,
                )) as Box<dyn Reply>)
            }
        )
}

pub fn get_processing<R: Renderer + Clone + Send + 'static, T: TokenGenerator>(
    render_engine: R,
    token_generator: T,
) -> impl Filter<Extract = (Box<dyn Reply>, String), Error = Rejection>
+ Clone {
    warp::get()
        .and(warp::path!("processing"))
        .and(warp::any().map(move || token_generator.clone().generate_token().unwrap()))
        .and(warp::query::<get::ProcessingQueryParams>())
        .and(warp::any().map(move || render_engine.clone()))
        .and_then(
            move |new_token: String,
                  query: get::ProcessingQueryParams,
                  render_engine: R| async move {

                let decoded_script = match query.script {
                    Some(encoded_script) => {
                        Some(percent_decode_str(encoded_script.as_str())
                            .decode_utf8()
                            .map_err(|_| warp::reject::custom(QueryParamValidationRejection))?
                            .to_string())
                    },
                    None => None
                };

                let decoded_html = match query.html {
                    Some(encoded_html) => {
                        Some(percent_decode_str(encoded_html.as_str())
                            .decode_utf8()
                            .map_err(|_| warp::reject::custom(QueryParamValidationRejection))?
                            .to_string())
                    },
                    None => None
                };

                Ok::<_, Rejection>((
                    Box::new(get::processing_reply(&new_token, decoded_script, decoded_html,  query.css, &render_engine)?)
                        as Box<dyn Reply>,
                    new_token,
                ))
            },
        )
        .untuple_one()
}

pub fn post<R: Renderer + Clone + Send + 'static, T: TokenGenerator, H: Storer, Q: Relayer>(
    render_engine: R,
    token_generator: T,
    storer: Arc<H>,
    relayer: Q,
) -> impl Filter<Extract = (Box<dyn Reply>, String, Option<String>, Option<String>), Error = Rejection>
       + Clone {
    warp::post()
        .and(warp::path!(String / String))
        .and(warp::query::<post::QueryParams>())
        .and(
            warp::filters::body::form::<post::BodyParams>()
                .and_then(move |body: post::BodyParams| async {
                    let path = body.path.clone();
                    Ok::<_, Rejection>((Data::try_from(body)?, path))
                })
                .or(warp::filters::multipart::form()
                    .max_length(1024 * 1024 * 16) // 16 MB
                    .and_then(|form: FormData| async {
                        let binary_type: Option<BinaryType> = None;
                        let binary_data: Option<String> = None;
                        let path: Option<String> = None;

                        let (binary_type, binary_data, path): (
                            Option<BinaryType>,
                            Option<String>,
                            Option<String>,
                        ) = form
                            .try_fold(
                                (binary_type, binary_data, path),
                                |(mut bt, mut bd, mut p), x| async move {
                                    let field_name = x.name().to_owned();
                                    let content_type = x.content_type();

                                    if field_name == "path" {
                                        let data = x
                                            .stream()
                                            .try_fold(Vec::new(), |mut vec, data| {
                                                vec.put(data);
                                                async move { Ok(vec) }
                                            })
                                            .await?;

                                        p = match std::str::from_utf8(&data) {
                                            Ok(d) => Some(d.to_string()),
                                            Err(_) => None,
                                        };
                                    } else if field_name == "value" {
                                        bt = match BinaryType::try_from(
                                            content_type.unwrap_or_default(),
                                        ) {
                                            Ok(binary_type) => Some(binary_type),
                                            Err(_) => None,
                                        };
                                        let data = x
                                            .stream()
                                            .try_fold(Vec::new(), |mut vec, data| {
                                                vec.put(data);
                                                async move { Ok(vec) }
                                            })
                                            .await?;
                                        bd = Some(base64::encode(data));
                                    }
                                    Ok((bt, bd, p))
                                },
                            )
                            .await
                            .map_err(|_| warp::reject::custom(BadRequestRejection))?;

                        let bd = BinaryData {
                            binary: binary_data
                                .ok_or_else(|| warp::reject::custom(BadRequestRejection))?,
                            binary_type: binary_type
                                .ok_or_else(|| warp::reject::custom(BadRequestRejection))?,
                        };
                        Ok::<_, Rejection>((
                            Data::Binary(Some(bd)),
                            path.ok_or_else(|| warp::reject::custom(BadRequestRejection))?,
                        ))
                    }))
                .unify(),
        )
        .and(warp::any().map(move || token_generator.clone().generate_token().unwrap()))
        .and(warp::any().map(move || render_engine.clone()))
        .and(warp::any().map(move || storer.clone()))
        .and(warp::any().map(move || relayer.clone()))
        .and_then(
            move |_query_data_path: String,
                  old_token: String,
                  query: post::QueryParams,
                  (data, path): (Data, String),
                  new_token: String,
                  render_engine: R,
                  storer: Arc<H>,
                  relayer: Q| async move {
                let key_entry = storer
                    .get::<SymmetricKey>(".keys.encryption.symmetric.default.")
                    .await
                    .map_err(CryptoErrorRejection)?;
                let (key, key_entry_path, _) = key_entry
                    .take_resolve_all()
                    .await
                    .map_err(CryptoErrorRejection)?;
                let algo_storer = (*storer).clone();
                let key_algo = key
                    .to_byte_algorithm(None, |key| async move {
                        key.to_ref_entry(key_entry_path, algo_storer)
                    })
                    .await
                    .map_err(CryptoErrorRejection)?;
                let data_clone = data.clone();
                let entry = data_clone
                    .to_sealed_entry(path.clone(), key_algo)
                    .await
                    .map_err(CryptoErrorRejection)?;
                storer.create(entry).await.map_err(CryptoErrorRejection)?;

                if let Some(relay_url) = query.relay_url.clone() {
                    relayer
                        .relay(path.clone(), relay_url)
                        .await
                        .map_err(|_| warp::reject::custom(RelayRejection))?;
                }

                let reply = post::reply(data, &path, &new_token, query, &render_engine)?;
                Ok::<_, Rejection>((
                    Box::new(reply) as Box<dyn Reply>,
                    format!("/secure/data/{}/{}", &path, &old_token),
                    Some(format!("/secure/data/{}/{}", &path, &new_token)),
                    Some(new_token),
                ))
            },
        )
        .untuple_one()
}
