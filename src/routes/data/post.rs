use crate::{
    render::{RenderTemplate, Rendered, Renderer, SecureTemplateValues, TemplateValues},
    routes::{
        BadRequestRejection, DataStorageErrorRejection, IframeTokensDoNotMatchRejection,
        SerializationRejection, SessionTokenNotFoundRejection,
    },
    token::TokenGenerator,
};
use redact_crypto::KeyStorer;
use redact_data::{Data, DataStorer, DataValue, StorageError};
use serde::{Deserialize, Serialize};
use std::convert::{From, TryFrom};
use warp::{Filter, Rejection, Reply};
use warp_sessions::{CookieOptions, SameSiteCookieOption, Session, SessionStore, SessionWithStore};
use std::collections::HashMap;
use crate::routes::error::RelayRejection;
use http::{StatusCode};

#[derive(Deserialize, Serialize)]
struct SubmitDataPathParams {
    token: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct SubmitDataBodyParams {
    path: String,
    value: Option<String>,
    value_type: String,
    relay_url: Option<String>,
}

impl TryFrom<SubmitDataBodyParams> for Data {
    type Error = BadRequestRejection;

    fn try_from(body: SubmitDataBodyParams) -> Result<Self, Self::Error> {
        if let Some(value) = body.value {
            let dv = match body.value_type.as_ref() {
                "bool" => DataValue::from(value.parse::<bool>().or(Err(BadRequestRejection))?),
                "u64" => DataValue::from(value.parse::<u64>().or(Err(BadRequestRejection))?),
                "i64" => DataValue::from(value.parse::<i64>().or(Err(BadRequestRejection))?),
                "f64" => DataValue::from(value.parse::<f64>().or(Err(BadRequestRejection))?),
                "string" => DataValue::from(value),
                _ => return Err(BadRequestRejection),
            };

            Ok(Data::new(&body.path, dv))
        } else {
            Ok(Data::new(&body.path, DataValue::from(false)))
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

pub fn submit_data<S: SessionStore, R: Renderer, T: TokenGenerator, D: DataStorer, K: KeyStorer>(
    session_store: S,
    render_engine: R,
    token_generator: T,
    data_store: D,
    keys_store: K,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::any()
        .and(warp::path!("data" / String).map(|token| SubmitDataPathParams { token }))
        .and(warp::query::<SubmitDataQueryParams>())
        .and(
            warp::filters::body::form::<SubmitDataBodyParams>().and_then(
                move |body: SubmitDataBodyParams| async {
                    let relay_url = body.relay_url.clone();
                    Ok::<_, Rejection>((relay_url, Data::try_from(body)?))
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
        .and(warp::any().map(move || data_store.clone()))
        .and(warp::any().map(move || keys_store.clone()))
        .and_then(
            move |path_params: SubmitDataPathParams,
                  query_params: SubmitDataQueryParams,
                  request_info: (Option<String>, Data),
                  session_with_store: SessionWithStore<S>,
                  token: String,
                  render_engine: R,
                  data_store: D,
                  key_store: K| async move {
                let data = request_info.1;
                let relay_url = request_info.0;

                match session_with_store.session.get("token") {
                    Some::<String>(session_token) => {
                        if session_token != path_params.token {
                            Err(warp::reject::custom(IframeTokensDoNotMatchRejection))
                        } else {
                            let res = data_store
                                .create(data.clone())
                                .await
                                .map_err(DataStorageErrorRejection);

                            match res {
                                Ok(_) => {
                                    let mut relay_err = false;
                                    if let Some(relay_url) = relay_url.clone() {
                                        let mut req_body = HashMap::new();
                                        req_body.insert("path", data.path());
                                        let client = reqwest::Client::new();
                                        let resp = client.post(relay_url.clone())
                                            .json(&req_body)
                                            .send()
                                            .await
                                            .map_err(|_| warp::reject::custom(RelayRejection))
                                            .and_then(|response| {
                                                if response.status() != StatusCode::OK {
                                                    Err(warp::reject::custom(RelayRejection))
                                                } else {
                                                    Ok(response)
                                                }
                                            });
                                        relay_err = resp.is_err();
                                    }

                                    if relay_err {
                                        Err(warp::reject::custom(RelayRejection))
                                    } else {
                                        Ok::<_, Rejection>((
                                            Rendered::new(
                                                render_engine,
                                                RenderTemplate {
                                                    name: "secure",
                                                    value: TemplateValues::Secure(
                                                        SecureTemplateValues {
                                                            data: Some(data.clone()),
                                                            path: Some(data.path()),
                                                            token: Some(token.clone()),
                                                            css: query_params.css,
                                                            edit: query_params.edit,
                                                            relay_url
                                                        },
                                                    ),
                                                },
                                            )?,
                                            path_params,
                                            token,
                                            session_with_store,
                                        ))
                                    }

                                }
                                Err(e) => Err(warp::reject::custom(e))
                            }
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
