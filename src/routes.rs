pub mod data {
    // pub mod post {
    //     use crate::render::Renderer;
    //     use crate::session::SessionStore;
    //     use serde::{Deserialize, Serialize};
    //     use warp::{Filter, Rejection, Reply};

    //     #[derive(Deserialize, Serialize)]
    //     struct SubmitDataQueryParams {
    //         css: Option<String>,
    //         edit: Option<bool>,
    //     }

    //     #[derive(Deserialize, Serialize)]
    //     struct SubmitDataPathParams {
    //         path: String,
    //     }

    //     pub fn submit_data<S: SessionStore, R: Renderer>(
    //         session_store: S,
    //         render_engine: R,
    //     ) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    //         warp::any().and(warp::path!("data" / String).map(|path| SubmitDataPathParams { path }))
    //     }
    // }
    pub mod get {
        use crate::render::{RenderTemplate, Rendered, Renderer};
        use crate::session::{
            self, CookieOptions, SameSiteCookieOption, SessionStore, SessionWithStore,
        };
        use crate::storage::Storer;
        use crate::token::TokenGenerator;
        use serde::{Deserialize, Serialize};
        use serde_json::Value::{Bool, Null, Number, String as SerdeString};
        use std::collections::HashMap;
        use warp::{Filter, Rejection, Reply};

        #[derive(Deserialize, Serialize)]
        struct WithoutTokenQueryParams {
            css: Option<String>,
            edit: Option<bool>,
        }

        #[derive(Deserialize, Serialize)]
        struct WithoutTokenPathParams {
            path: String,
        }

        #[derive(Deserialize, Serialize)]
        struct WithTokenQueryParams {
            css: Option<String>,
            edit: Option<bool>,
        }

        #[derive(Deserialize, Serialize)]
        struct WithTokenPathParams {
            path: String,
            token: String,
        }

        pub fn without_token<S: SessionStore, R: Renderer, T: TokenGenerator>(
            session_store: S,
            render_engine: R,
            token_generator: T,
        ) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
            warp::any()
                .and(warp::path!("data" / String).map(|path| WithoutTokenPathParams { path }))
                .and(warp::query::<WithoutTokenQueryParams>())
                .and(session::request::with_session(
                    session_store,
                    Some(CookieOptions {
                        cookie_name: "sid".to_string(),
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
                .and_then(
                    move |path_params: WithoutTokenPathParams,
                          query_params: WithoutTokenQueryParams,
                          session_with_store: SessionWithStore<S>,
                          token: String,
                          render_engine: R| async move {
                        let mut template_values = HashMap::new();
                        template_values.insert("path".to_string(), path_params.path.clone());
                        template_values.insert("token".to_string(), token.clone());

                        match query_params.css {
                            Some(css) => template_values.insert("css".to_string(), css),
                            _ => None,
                        };
                        match query_params.edit {
                            Some(edit) => {
                                template_values.insert("edit".to_string(), edit.to_string())
                            }
                            _ => None,
                        };

                        Ok::<_, Rejection>((
                            Rendered::new(
                                render_engine,
                                RenderTemplate {
                                    name: "unsecure",
                                    value: template_values,
                                },
                            )?,
                            path_params,
                            session_with_store,
                            token,
                        ))
                    },
                )
                .untuple_one()
                .and_then(
                    move |reply: Rendered,
                          path_params: WithoutTokenPathParams,
                          mut session_with_store: SessionWithStore<S>,
                          token: String| async move {
                        session_with_store
                            .session
                            .insert("token", token.clone())
                            .map_err(|_| warp::reject())?;
                        session_with_store.cookie_options.path = Some(format!(
                            "/data/{}/{}",
                            path_params.path.clone(),
                            token.clone()
                        ));

                        Ok::<_, Rejection>((reply, session_with_store))
                    },
                )
                .untuple_one()
                .and_then(session::reply::with_session)
        }

        pub fn with_token<S: SessionStore, R: Renderer, T: Storer>(
            session_store: S,
            render_engine: R,
            data_store: T,
        ) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
            warp::any()
                .and(
                    warp::path!("data" / String / String)
                        .map(|path, token| WithTokenPathParams { path, token }),
                )
                .and(warp::query::<WithTokenQueryParams>())
                .and(session::request::with_session(
                    session_store,
                    Some(CookieOptions {
                        cookie_name: "sid".to_string(),
                        cookie_value: None,
                        max_age: Some(60),
                        domain: None,
                        path: None,
                        secure: false,
                        http_only: true,
                        same_site: Some(SameSiteCookieOption::Strict),
                    }),
                ))
                .and(warp::any().map(move || render_engine.clone()))
                .and(warp::any().map(move || data_store.clone()))
                .and_then(
                    move |path_params: WithTokenPathParams,
                          query_params: WithTokenQueryParams,
                          session_with_store: SessionWithStore<S>,
                          render_engine: R,
                          data_store: T| async move {
                        let mut template_values = HashMap::new();
                        match query_params.css {
                            Some(css) => template_values.insert("css".to_string(), css),
                            _ => None,
                        };
                        match query_params.edit {
                            Some(edit) => {
                                if edit {
                                    template_values.insert("edit".to_string(), "true".to_string());
                                }
                            }
                            _ => (),
                        };
                        template_values.insert("path".to_string(), path_params.path.clone());

                        match session_with_store.session.get("token") {
                            Some::<String>(session_token) => {
                                if session_token != path_params.token {
                                    template_values.insert("data".to_string(), "".to_string());
                                    Ok::<_, Rejection>((
                                        Rendered::new(
                                            render_engine,
                                            RenderTemplate {
                                                name: "secure",
                                                value: template_values,
                                            },
                                        )?,
                                        path_params,
                                        session_with_store,
                                    ))
                                } else {
                                    data_store.get(&path_params.path).await.map(|data| {
                                        let val = match data.value {
                                            Null => "".to_string(),
                                            Bool(b) => b.to_string(),
                                            Number(n) => n.to_string(),
                                            SerdeString(s) => s.to_string(),
                                            _ => "".to_string(),
                                        };
                                        template_values.insert("data".to_string(), val);
                                        Ok::<_, Rejection>((
                                            Rendered::new(
                                                render_engine,
                                                RenderTemplate {
                                                    name: "secure",
                                                    value: template_values,
                                                },
                                            )?,
                                            path_params,
                                            session_with_store,
                                        ))
                                    })?
                                }
                            }
                            None => {
                                template_values.insert("data".to_string(), "".to_string());
                                Ok::<_, Rejection>((
                                    Rendered::new(
                                        render_engine,
                                        RenderTemplate {
                                            name: "secure",
                                            value: template_values,
                                        },
                                    )?,
                                    path_params,
                                    session_with_store,
                                ))
                            }
                        }
                    },
                )
                .untuple_one()
                .and_then(
                    move |reply: Rendered,
                          path_params: WithTokenPathParams,
                          mut session_with_store: SessionWithStore<S>| async move {
                        session_with_store.cookie_options.path = Some(format!(
                            "/data/{}/{}",
                            path_params.path.clone(),
                            path_params.token.clone()
                        ));
                        session_with_store.session.destroy();
                        Ok::<_, Rejection>((reply, session_with_store))
                    },
                )
                .untuple_one()
                .and_then(session::reply::with_session)
        }
    }
}
