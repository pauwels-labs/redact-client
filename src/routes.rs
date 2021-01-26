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
                .and_then(warp_sessions::reply::with_session)
        }

        pub fn with_token<S: SessionStore, R: Renderer, T: TokenGenerator, D: Storer>(
            session_store: S,
            render_engine: R,
            token_generator: T,
            data_store: D,
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
                .and_then(
                    move |path_params: WithTokenPathParams,
                          query_params: WithTokenQueryParams,
                          session_with_store: SessionWithStore<S>,
                          token: String,
                          render_engine: R,
                          data_store: D| async move {
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

#[cfg(test)]
mod test {
    mod get {
        mod with_token {
            use crate::render::{tests::MockRenderer, RenderTemplate};
            use crate::routes::data::get;
            use crate::token::tests::MockTokenGenerator;
            use std::collections::HashMap;
            use std::sync::Arc;
            use warp_sessions::MemoryStore;

            #[tokio::test]
            async fn with_token_with_no_query_params() {
                let session_store = MemoryStore::new();
                let mut render_engine = MockRenderer::new();
                render_engine
                    .expect_render()
                    .withf(move |template: &RenderTemplate<HashMap<String, String>>| {
                        let mut expected_value = HashMap::new();
                        expected_value.insert("path".to_string(), ".testKey.".to_string());
                        expected_value.insert(
                            "token".to_string(),
                            "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C"
                                .to_string(),
                        );
                        template.value == expected_value
                    })
                    .times(1)
                    .return_once(move |_| Ok("".to_string()));

                let mut token_generator = MockTokenGenerator::new();
                token_generator
                    .expect_generate_token()
                    .times(1)
                    .returning(|| {
                        Ok(
                            "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C"
                                .to_owned(),
                        )
                    });

                let with_token_filter = get::with_token(
                    session_store,
                    Arc::new(render_engine),
                    Arc::new(token_generator),
                );

                let res = warp::test::request()
                    .path("/data/.testKey.")
                    .reply(&with_token_filter)
                    .await;
                assert_eq!(res.status(), 200);
            }
        }

        mod without_token {
            use crate::render::{tests::MockRenderer, RenderTemplate};
            use crate::routes::data::get;
            use crate::token::tests::MockTokenGenerator;
            use std::collections::HashMap;
            use std::sync::Arc;
            use warp_sessions::MemoryStore;

            #[tokio::test]
            async fn without_token_with_no_query_params() {
                let session_store = MemoryStore::new();
                let mut render_engine = MockRenderer::new();
                render_engine
                    .expect_render()
                    .withf(move |template: &RenderTemplate<HashMap<String, String>>| {
                        let mut expected_value = HashMap::new();
                        expected_value.insert("path".to_string(), ".testKey.".to_string());
                        expected_value.insert(
                            "token".to_string(),
                            "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C"
                                .to_string(),
                        );
                        template.value == expected_value
                    })
                    .times(1)
                    .return_once(move |_| Ok("".to_string()));

                let mut token_generator = MockTokenGenerator::new();
                token_generator
                    .expect_generate_token()
                    .times(1)
                    .returning(|| {
                        Ok(
                            "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C"
                                .to_owned(),
                        )
                    });

                let without_token_filter = get::without_token(
                    session_store,
                    Arc::new(render_engine),
                    Arc::new(token_generator),
                );

                let res = warp::test::request()
                    .path("/data/.testKey.")
                    .reply(&without_token_filter)
                    .await;
                assert_eq!(res.status(), 200);
            }

            #[tokio::test]
            async fn without_token_with_css() {
                let session_store = MemoryStore::new();
                let mut render_engine = MockRenderer::new();
                render_engine
                    .expect_render()
                    .withf(move |template: &RenderTemplate<HashMap<String, String>>| {
                        let mut expected_value = HashMap::new();
                        expected_value.insert("path".to_owned(), ".testKey.".to_owned());
                        expected_value.insert(
                            "token".to_owned(),
                            "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C"
                                .to_owned(),
                        );
                        expected_value.insert("css".to_owned(), "p { color: red; }".to_owned());
                        template.value == expected_value
                    })
                    .times(1)
                    .return_once(move |_| Ok("".to_string()));

                let mut token_generator = MockTokenGenerator::new();
                token_generator
                    .expect_generate_token()
                    .times(1)
                    .returning(|| {
                        Ok(
                            "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C"
                                .to_owned(),
                        )
                    });

                let without_token_filter = get::without_token(
                    session_store,
                    Arc::new(render_engine),
                    Arc::new(token_generator),
                );

                let res = warp::test::request()
                    .path("/data/.testKey.?css=p%20%7B%20color%3A%20red%3B%20%7D")
                    .reply(&without_token_filter)
                    .await;
                assert_eq!(res.status(), 200);
            }

            #[tokio::test]
            async fn test_without_token_with_edit_true() {
                let session_store = MemoryStore::new();
                let mut render_engine = MockRenderer::new();
                render_engine
                    .expect_render()
                    .withf(move |template: &RenderTemplate<HashMap<String, String>>| {
                        let mut expected_value = HashMap::new();
                        expected_value.insert("path".to_owned(), ".testKey.".to_owned());
                        expected_value.insert(
                            "token".to_owned(),
                            "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C"
                                .to_owned(),
                        );
                        expected_value.insert("edit".to_owned(), "true".to_owned());
                        template.value == expected_value
                    })
                    .times(1)
                    .return_once(move |_| Ok("".to_string()));

                let mut token_generator = MockTokenGenerator::new();
                token_generator
                    .expect_generate_token()
                    .times(1)
                    .returning(|| {
                        Ok(
                            "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C"
                                .to_owned(),
                        )
                    });

                let without_token_filter = get::without_token(
                    session_store,
                    Arc::new(render_engine),
                    Arc::new(token_generator),
                );

                let res = warp::test::request()
                    .path("/data/.testKey.?edit=true")
                    .reply(&without_token_filter)
                    .await;
                assert_eq!(res.status(), 200);
            }

            #[tokio::test]
            async fn test_without_token_with_edit_false() {
                let session_store = MemoryStore::new();
                let mut render_engine = MockRenderer::new();
                render_engine
                    .expect_render()
                    .withf(move |template: &RenderTemplate<HashMap<String, String>>| {
                        let mut expected_value = HashMap::new();
                        expected_value.insert("path".to_owned(), ".testKey.".to_owned());
                        expected_value.insert(
                            "token".to_owned(),
                            "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C"
                                .to_owned(),
                        );
                        expected_value.insert("edit".to_owned(), "false".to_owned());
                        template.value == expected_value
                    })
                    .times(1)
                    .return_once(move |_| Ok("".to_string()));

                let mut token_generator = MockTokenGenerator::new();
                token_generator
                    .expect_generate_token()
                    .times(1)
                    .returning(|| {
                        Ok(
                            "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C"
                                .to_owned(),
                        )
                    });

                let without_token_filter = get::without_token(
                    session_store,
                    Arc::new(render_engine),
                    Arc::new(token_generator),
                );

                let res = warp::test::request()
                    .path("/data/.testKey.?edit=false")
                    .reply(&without_token_filter)
                    .await;
                assert_eq!(res.status(), 200);
            }
        }
    }
}
