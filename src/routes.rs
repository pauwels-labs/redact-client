pub mod data {
    pub mod post {
        use crate::render::{RenderTemplate, Rendered, Renderer};
        use crate::storage::{Data, Storer};
        use crate::token::TokenGenerator;
        use serde::{Deserialize, Serialize};
        use serde_json::Value;
        use std::collections::HashMap;
        use warp::{Filter, Rejection, Reply};
        use warp_sessions::{
            CookieOptions, SameSiteCookieOption, Session, SessionStore, SessionWithStore,
        };

        #[derive(Deserialize, Serialize)]
        struct SubmitDataPathParams {
            path: String,
            token: String,
        }

        #[derive(Deserialize, Serialize)]
        struct SubmitDataBodyParams {
            data: Value,
            data_type: String,
        }

        pub fn submit_data<S: SessionStore, R: Renderer, T: TokenGenerator, D: Storer>(
            session_store: S,
            render_engine: R,
            token_generator: T,
            data_store: D,
        ) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
            warp::any()
                .and(
                    warp::path!("data" / String / String)
                        .map(|path, token| SubmitDataPathParams { path, token }),
                )
                .and(warp::filters::body::form::<SubmitDataBodyParams>())
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
                .and_then(
                    move |path_params: SubmitDataPathParams,
                          body_params: SubmitDataBodyParams,
                          session_with_store: SessionWithStore<S>,
                          token: String,
                          render_engine: R,
                          data_store: D| async move {
                        let data_str = match body_params.data.as_str() {
                            Some(s) => s,
                            None => "",
                        };

                        let mut template_values = HashMap::new();
                        template_values.insert("path".to_string(), path_params.path.clone());
                        template_values.insert("data".to_string(), data_str.to_string());
                        template_values
                            .insert("data_type".to_string(), body_params.data_type.clone());
                        template_values.insert("edit".to_string(), "true".to_string());
                        template_values.insert("token".to_string(), token.clone());
                        match session_with_store.session.get("token") {
                            Some::<String>(session_token) => {
                                if session_token != path_params.token {
                                    Ok::<_, Rejection>((
                                        Rendered::new(
                                            render_engine,
                                            RenderTemplate {
                                                name: "secure",
                                                value: template_values,
                                            },
                                        )?,
                                        path_params,
                                        token,
                                        session_with_store,
                                    ))
                                } else {
                                    data_store
                                        .create(
                                            &path_params.path,
                                            Data {
                                                data_type: body_params.data_type.clone(),
                                                path: path_params.path.clone(),
                                                value: body_params.data.clone(),
                                            },
                                        )
                                        .await
                                        .map(|_| {
                                            Ok::<_, Rejection>((
                                                Rendered::new(
                                                    render_engine,
                                                    RenderTemplate {
                                                        name: "secure",
                                                        value: template_values,
                                                    },
                                                )?,
                                                path_params,
                                                token,
                                                session_with_store,
                                            ))
                                        })?
                                }
                            }
                            None => Ok::<_, Rejection>((
                                Rendered::new(
                                    render_engine,
                                    RenderTemplate {
                                        name: "secure",
                                        value: template_values,
                                    },
                                )?,
                                path_params,
                                token,
                                session_with_store,
                            )),
                        }
                    },
                )
                .untuple_one()
                .and_then(
                    move |reply: Rendered,
                          path_params: SubmitDataPathParams,
                          token: String,
                          mut session_with_store: SessionWithStore<S>| async move {
                        session_with_store.cookie_options.path = Some(format!(
                            "/data/{}/{}",
                            path_params.path.clone(),
                            path_params.token.clone()
                        ));
                        session_with_store.session.destroy();

                        let mut new_session = SessionWithStore::<S> {
                            session: Session::new(),
                            session_store: session_with_store.session_store.clone(),
                            cookie_options: CookieOptions {
                                cookie_name: "sid",
                                cookie_value: None,
                                max_age: Some(60),
                                domain: None,
                                path: Some(format!(
                                    "/data/{}/{}",
                                    path_params.path.clone(),
                                    token.clone()
                                )),
                                secure: false,
                                http_only: true,
                                same_site: Some(SameSiteCookieOption::Strict),
                            },
                        };

                        new_session
                            .session
                            .insert("token", token)
                            .map_err(|_| warp::reject())?;
                        Ok::<_, Rejection>((
                            warp_sessions::reply::with_session(reply, session_with_store).await?,
                            new_session,
                        ))
                    },
                )
                .untuple_one()
                .and_then(warp_sessions::reply::with_session)
        }
    }
    pub mod get {
        use crate::render::{RenderTemplate, Rendered, Renderer};
        use crate::storage::Storer;
        use crate::token::TokenGenerator;
        use serde::{Deserialize, Serialize};
        use std::collections::HashMap;
        use warp::{Filter, Rejection, Reply};
        use warp_sessions::{
            self, CookieOptions, SameSiteCookieOption, Session, SessionStore, SessionWithStore,
        };
        use crate::redis_client::FetchCache;
        use futures::executor::block_on;

        const PAGE_SIZE: u8 = 10; // TODO: this shouldn't be a constant and is already being pulled from config for storage&redis

        #[derive(Deserialize, Serialize)]
        struct WithoutTokenQueryParams {
            css: Option<String>,
            edit: Option<bool>,
            fetch_id: Option<String>,
            index: Option<i64>,
        }

        #[derive(Deserialize, Serialize)]
        struct WithoutTokenPathParams {
            path: String,
        }

        #[derive(Deserialize, Serialize)]
        struct WithTokenQueryParams {
            css: Option<String>,
            edit: Option<bool>,
            index: Option<i64>,
            fetch_id: Option<String>,
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
                            Some(edit) => template_values.insert("edit".to_string(), edit.to_string()),
                            _ => None,
                        };
                        match query_params.index {
                            Some(index) => template_values.insert("index".to_string(), index.to_string()),
                            _ => None,
                        };
                        match query_params.fetch_id {
                            Some(fetch_id) => template_values.insert("fetch_id".to_string(), fetch_id.to_string()),
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
                .and_then(warp_sessions::reply::with_session)
        }

        pub fn with_token<S: SessionStore, R: Renderer, T: TokenGenerator, D: Storer, F: FetchCache>(
            session_store: S,
            render_engine: R,
            token_generator: T,
            data_store: D,
            redis_client: F,
        ) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
            warp::any()
                .and(
                    warp::path!("data" / String / String)
                        .map(|path, token| WithTokenPathParams { path, token }),
                )
                .and(warp::query::<WithTokenQueryParams>())
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
                .and(warp::any().map(move || redis_client.clone()))
                .and_then(
                    move |path_params: WithTokenPathParams,
                          query_params: WithTokenQueryParams,
                          session_with_store: SessionWithStore<S>,
                          token: String,
                          render_engine: R,
                          data_store: D,
                          redis_client: F | async move {
                        let mut template_values = HashMap::new();
                        match &query_params.css {
                            Some(css) => template_values.insert("css".to_string(), css.to_owned()),
                            _ => None,
                        };
                        match &query_params.edit {
                            Some(edit) => {
                                if *edit {
                                    template_values.insert("edit".to_string(), "true".to_string());
                                    template_values.insert("token".to_string(), token.clone());
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
                                        query_params,
                                        token,
                                        session_with_store,
                                    ))
                                } else {
                                    // ----- start request query validation code -----
                                    let mut is_valid_request = true;
                                    match (&query_params.fetch_id, query_params.index) {
                                        (Some(_fetch_id), None) => is_valid_request = false,
                                        (None, Some(_index)) => is_valid_request = false,
                                        _ => (),
                                    }

                                    if !is_valid_request {
                                        return Ok::<_, Rejection>((
                                            Rendered::new(
                                                render_engine,
                                                RenderTemplate {
                                                    name: "secure",
                                                    value: template_values,
                                                },
                                            )?,
                                            path_params,
                                            query_params,
                                            token.clone(),
                                            session_with_store,
                                        ));
                                    }
                                    // ----- end request query validation code -----

                                    // ----- start repository code -----
                                    match (&query_params.fetch_id, query_params.index) {
                                        // Collection request
                                        (Some(fetch_id), Some(index)) => {

                                            match block_on(redis_client.exists_index(fetch_id, index)).unwrap() {
                                                true => {
                                                    let (value, data_type): (String, String) = block_on(redis_client.get_index(fetch_id, index)).map_or_else(
                                                        |e| ("".to_string(), "string".to_string()),
                                                        | data| {
                                                            let val_str = match data.value.as_str() {
                                                                Some(s) => s.to_owned(),
                                                                None => "".to_string(),
                                                            };
                                                            let data_type = data.data_type;
                                                            (val_str, data_type)
                                                        }
                                                    );

                                                    template_values.insert("data".to_string(), value);
                                                    template_values.insert("data_type".to_string(), data_type);
                                                },
                                                false => {
                                                    let page_start_index = index / i64::from(PAGE_SIZE);
                                                    let (value, data_type): (String, String) =
                                                        data_store.get_collection(&path_params.path, page_start_index).await.map_or_else(
                                                            |e| ("".to_string(), "string".to_string()),
                                                            | data| {

                                                                // TODO: don't block, handle (or just log) error
                                                                match block_on(redis_client.set(fetch_id, page_start_index,  &data.results.clone(), 60)) {
                                                                    Ok(_) => println!("cache put success"),
                                                                    Err(_) => println!("Error updating fetch cache")
                                                                }

                                                                let page_index = index % i64::from(PAGE_SIZE);
                                                                let result_at_index = data.results[page_index as usize].clone();
                                                                let val_str = match result_at_index.value.as_str() {
                                                                    Some(s) => s.to_owned(),
                                                                    None => "".to_string(),
                                                                };
                                                                (val_str, result_at_index.data_type)
                                                            },
                                                        );

                                                    template_values.insert("data".to_string(), value);
                                                    template_values.insert("data_type".to_string(), data_type);
                                                }
                                            }



                                        },
                                        _ => {
                                            // Non-collection request
                                            let (value, data_type): (String, String) =
                                                data_store.get(&path_params.path).await.map_or_else(
                                                    |_| ("".to_string(), "string".to_string()),
                                                    |data| {
                                                        let val_str = match data.value.as_str() {
                                                            Some(s) => s.to_owned(),
                                                            None => "".to_string(),
                                                        };
                                                        (val_str, data.data_type)
                                                    },
                                                );
                                            template_values.insert("data".to_string(), value);
                                            template_values.insert("data_type".to_string(), data_type);
                                        },
                                    }

                                    Ok::<_, Rejection>((
                                        Rendered::new(
                                            render_engine,
                                            RenderTemplate {
                                                name: "secure",
                                                value: template_values,
                                            },
                                        )?,
                                        path_params,
                                        query_params,
                                        token.clone(),
                                        session_with_store,
                                    ))

                                    // ----- end repository code -----
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
                                    query_params,
                                    token,
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
                          query_params: WithTokenQueryParams,
                          token: String,
                          mut session_with_store: SessionWithStore<S>| async move {
                        session_with_store.cookie_options.path = Some(format!(
                            "/data/{}/{}",
                            path_params.path.clone(),
                            path_params.token.clone()
                        ));
                        session_with_store.session.destroy();

                        let mut new_session = SessionWithStore::<S> {
                            session: Session::new(),
                            session_store: session_with_store.session_store.clone(),
                            cookie_options: CookieOptions {
                                cookie_name: "sid",
                                cookie_value: None,
                                max_age: Some(60),
                                domain: None,
                                path: Some(format!(
                                    "/data/{}/{}",
                                    path_params.path.clone(),
                                    token.clone()
                                )),
                                secure: false,
                                http_only: true,
                                same_site: Some(SameSiteCookieOption::Strict),
                            },
                        };

                        // Only add a new session cookie if editing
                        let edit = match query_params.edit {
                            Some(e) => e,
                            None => false,
                        };
                        if edit {
                            new_session
                                .session
                                .insert("token", token)
                                .map_err(|_| warp::reject())?;
                        }
                        Ok::<_, Rejection>((
                            warp_sessions::reply::with_session(reply, session_with_store).await?,
                            new_session,
                        ))
                    },
                )
                .untuple_one()
                .and_then(warp_sessions::reply::with_session)
        }
    }
}