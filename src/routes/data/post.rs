use crate::{
    render::{RenderTemplate, Rendered, Renderer, SecureTemplateValues, TemplateValues},
    routes::{
        BadRequestRejection, CryptoErrorRejection, IframeTokensDoNotMatchRejection,
        SerializationRejection, SessionTokenNotFoundRejection, StorageErrorRejection,
    },
    token::TokenGenerator,
};
use redact_crypto::{Buildable, Data, States, Storer, SymmetricKey, SymmetricSealer, TypeBuilder};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use warp::{Filter, Rejection, Reply};
use warp_sessions::{CookieOptions, SameSiteCookieOption, Session, SessionStore, SessionWithStore};

#[derive(Deserialize, Serialize)]
struct SubmitDataPathParams {
    token: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct SubmitDataBodyParams {
    path: String,
    value: Option<String>,
    value_type: String,
}

impl TryFrom<SubmitDataBodyParams> for Data {
    type Error = BadRequestRejection;

    fn try_from(body: SubmitDataBodyParams) -> Result<Self, Self::Error> {
        if let Some(value) = body.value {
            Ok(match body.value_type.as_ref() {
                "bool" => Data::Bool(value.parse::<bool>().or(Err(BadRequestRejection))?),
                "u64" => Data::U64(value.parse::<u64>().or(Err(BadRequestRejection))?),
                "i64" => Data::I64(value.parse::<i64>().or(Err(BadRequestRejection))?),
                "f64" => Data::F64(value.parse::<f64>().or(Err(BadRequestRejection))?),
                "string" => Data::String(value),
                _ => return Err(BadRequestRejection),
            })
        } else {
            Ok(Data::Bool(false))
        }
    }
}

#[derive(Deserialize, Serialize)]
struct SubmitDataQueryParams {
    css: Option<String>,
    edit: Option<bool>,
    index: Option<i64>,
    fetch_id: Option<String>,
}

pub fn submit_data<S: SessionStore, R: Renderer, T: TokenGenerator, H: Storer>(
    session_store: S,
    render_engine: R,
    token_generator: T,
    storer: H,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::any()
        .and(warp::path!("data" / String).map(|token| SubmitDataPathParams { token }))
        .and(warp::query::<SubmitDataQueryParams>())
        .and(
            warp::filters::body::form::<SubmitDataBodyParams>().and_then(
                move |body: SubmitDataBodyParams| async {
                    let data_path = body.path.clone();
                    Ok::<_, Rejection>((Data::try_from(body)?, data_path))
                },
            ),
        )
        .and(warp_sessions::request::with_session(
            session_store,
            Some(CookieOptions {
                cookie_name: "sid",
                cookie_value: None,
                max_age: Some(60),
                domain: None,
                path: None,
                secure: false,
                http_only: true,
                same_site: Some(SameSiteCookieOption::Strict),
            }),
        ))
        .and(warp::any().map(move || token_generator.clone().generate_token().unwrap()))
        .and(warp::any().map(move || render_engine.clone()))
        .and(warp::any().map(move || storer.clone()))
        .and_then(
            move |path_params: SubmitDataPathParams,
                  query_params: SubmitDataQueryParams,
                  (data, data_path): (Data, String),
                  session_with_store: SessionWithStore<S>,
                  token: String,
                  render_engine: R,
                  storer: H| async move {
                match session_with_store.session.get("token") {
                    Some::<String>(session_token) => {
                        if session_token != path_params.token {
                            Err(warp::reject::custom(IframeTokensDoNotMatchRejection))
                        } else {
                            let key_entry = storer
                                .get::<SymmetricKey>(".keys.default")
                                .await
                                .map_err(StorageErrorRejection)?;
                            let key: SymmetricKey = storer
                                .resolve(key_entry.value.clone())
                                .await
                                .map_err(StorageErrorRejection)?;
                            let builder = TypeBuilder::Data(data.builder());
                            let unsealable = key
                                .seal(data.clone().into(), Some(key_entry.path))
                                .map_err(CryptoErrorRejection)?;

                            storer
                                .create(
                                    data_path.clone(),
                                    States::Sealed {
                                        builder,
                                        unsealable,
                                    },
                                )
                                .await
                                .map_err(StorageErrorRejection)
                                .map(|_| {
                                    Ok::<_, Rejection>((
                                        Rendered::new(
                                            render_engine,
                                            RenderTemplate {
                                                name: "secure",
                                                value: TemplateValues::Secure(
                                                    SecureTemplateValues {
                                                        data: Some(data),
                                                        path: Some(data_path),
                                                        token: Some(token.clone()),
                                                        css: query_params.css,
                                                        edit: query_params.edit,
                                                    },
                                                ),
                                            },
                                        )?,
                                        path_params,
                                        token,
                                        session_with_store,
                                    ))
                                })?
                        }
                    }
                    None => Err(warp::reject::custom(SessionTokenNotFoundRejection)),
                }
            },
        )
        .untuple_one()
        .and_then(
            move |reply: Rendered,
                  path_params: SubmitDataPathParams,
                  token: String,
                  mut session_with_store: SessionWithStore<S>| async move {
                session_with_store.cookie_options.path =
                    Some(format!("/data/{}", path_params.token.clone()));
                session_with_store.session.destroy();

                let mut new_session = SessionWithStore::<S> {
                    session: Session::new(),
                    session_store: session_with_store.session_store.clone(),
                    cookie_options: CookieOptions {
                        cookie_name: "sid",
                        cookie_value: None,
                        max_age: Some(60),
                        domain: None,
                        path: Some(format!("/data/{}", token.clone())),
                        secure: false,
                        http_only: true,
                        same_site: Some(SameSiteCookieOption::Strict),
                    },
                };

                new_session
                    .session
                    .insert("token", token)
                    .map_err(SerializationRejection)?;
                Ok::<_, Rejection>((
                    warp_sessions::reply::with_session(reply, session_with_store).await?,
                    new_session,
                ))
            },
        )
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
}
