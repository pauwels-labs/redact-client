use crate::{
    render::{RenderTemplate, Rendered, Renderer, SecureTemplateValues},
    routes::{
        DataStorageErrorRejection, IframeTokensDoNotMatchRejection, SerializationRejection,
        SessionTokenNotFoundRejection,
    },
    token::TokenGenerator,
};
use redact_crypto::KeyStorer;
use redact_data::{Data, DataStorer};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use warp::{Filter, Rejection, Reply};
use warp_sessions::{CookieOptions, SameSiteCookieOption, Session, SessionStore, SessionWithStore};

#[derive(Deserialize, Serialize)]
struct SubmitDataPathParams {
    token: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct SubmitDataBodyParams {
    data: Value,
    data_type: String,
    encrypted_by: Vec<String>,
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
        .and(warp::filters::body::form::<Data>())
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
                  data: Data,
                  session_with_store: SessionWithStore<S>,
                  token: String,
                  render_engine: R,
                  data_store: D,
                  keys_store: K| async move {
                match session_with_store.session.get("token") {
                    Some::<String>(session_token) => {
                        if session_token != path_params.token {
                            Err(IframeTokensDoNotMatchRejection)?
                            // Ok::<_, Rejection>((
                            //     Rendered::new(
                            //         render_engine,
                            //         RenderTemplate {
                            //             name: "unsecure",
                            //             value: SecureTemplateValues {
                            //                 data: None,
                            //                 path: None,
                            //                 token: None,
                            //                 css: query_params.css,
                            //                 edit: query_params.edit,
                            //             },
                            //         },
                            //     )?,
                            //     data,
                            //     path_params,
                            //     "".to_owned(),
                            //     session_with_store,
                            // ))
                        } else {
                            // let mut encrypted_by = None;
                            // if let Some(edit) = query_params.edit {
                            //     if edit {
                            //         if let Ok(keys) = keys_store.list().await {
                            //             encrypted_by = Some(
                            //                 keys.results
                            //                     .iter()
                            //                     .map(|key| key.name().to_owned())
                            //                     .collect(),
                            //             );
                            //         }
                            //     }
                            // }
                            // data.en

                            data_store
                                .create(data.clone())
                                .await
                                .map_err(DataStorageErrorRejection)
                                .map(|_| {
                                    Ok::<_, Rejection>((
                                        Rendered::new(
                                            render_engine,
                                            RenderTemplate {
                                                name: "secure",
                                                value: SecureTemplateValues {
                                                    data: Some(data.clone()),
                                                    path: Some(data.path.to_string()),
                                                    token: Some(token.clone()),
                                                    css: query_params.css,
                                                    edit: query_params.edit,
                                                },
                                            },
                                        )?,
                                        path_params,
                                        token,
                                        session_with_store,
                                    ))
                                })?
                        }
                    }
                    None => Err(SessionTokenNotFoundRejection)?
		    // 	Ok::<_, Rejection>((
                    //     Rendered::new(
                    //         render_engine,
                    //         RenderTemplate {
                    //             name: "secure",
                    //             value: SecureTemplateValues {
                    //                 data: None,
                    //                 path: None,
                    //                 token: None,
                    //                 css: query_params.css,
                    //                 edit: query_params.edit,
                    //             },
                    //         },
                    //     )?,
                    //     data,
                    //     path_params,
                    //     "".to_owned(),
                    //     session_with_store,
                    // )),
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
