pub mod data {
    pub mod post {
        use crate::render::{RenderTemplate, Rendered, Renderer, SecureTemplateValues};
        use crate::storage::{Data, DataStorer, KeyStorer};
        use crate::token::TokenGenerator;
        use serde::{Deserialize, Serialize};
        use serde_json::Value;
        use warp::{Filter, Rejection, Reply};
        use warp_sessions::{
            CookieOptions, SameSiteCookieOption, Session, SessionStore, SessionWithStore,
        };

        #[derive(Deserialize, Serialize)]
        struct SubmitDataPathParams {
            path: String,
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

        pub fn submit_data<
            S: SessionStore,
            R: Renderer,
            T: TokenGenerator,
            D: DataStorer,
            K: KeyStorer,
        >(
            session_store: S,
            render_engine: R,
            token_generator: T,
            data_store: D,
            keys_store: K,
        ) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
            warp::any()
                .and(
                    warp::path!("data" / String / String)
                        .map(|path, token| SubmitDataPathParams { path, token }),
                )
                .and(warp::query::<SubmitDataQueryParams>())
                .and(warp::filters::body::form::<Vec<(String, String)>>())
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
                          mut query_params: SubmitDataQueryParams,
                          body_params: Vec<(String, String)>,
                          session_with_store: SessionWithStore<S>,
                          token: String,
                          render_engine: R,
                          data_store: D,
                          keys_store: K| async move {
                        let mut data = None;
                        let mut data_type = None;
                        let mut encrypted_by: Vec<String> = Vec::new();
                        body_params.iter().for_each(|param| {
                            if param.0 == "data" {
                                data = Some(param.1.clone());
                            } else if param.0 == "data_type" {
                                data_type = Some(param.1.clone());
                            } else if param.0 == "encrypted_by" {
                                encrypted_by.push(param.1.clone());
                            }
                        });
                        let body_params = match (data, data_type) {
                            (Some(data), Some(data_type)) => Ok(SubmitDataBodyParams {
                                data: data.into(),
                                data_type,
                                encrypted_by,
                            }),
                            _ => Err(warp::reject()),
                        }?;
                        let data_str = if let Some(s) = body_params.data.as_str() {
                            s
                        } else {
                            ""
                        };

                        query_params.edit = Some(true);
                        let mut template_values = SecureTemplateValues {
                            path: path_params.path.clone(),
                            data: data_str.to_owned(),
                            data_type: body_params.data_type.clone(),
                            edit: query_params.edit,
                            token: token.clone(),
                            css: None,
                            encrypted_by: None,
                        };
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
                                    let mut encrypted_by = None;
                                    if let Some(edit) = query_params.edit {
                                        if edit {
                                            if let Ok(keys) = keys_store.list().await {
                                                encrypted_by = Some(
                                                    keys.results
                                                        .iter()
                                                        .map(|key| key.name().to_owned())
                                                        .collect(),
                                                );
                                            }
                                        }
                                    }
                                    template_values.encrypted_by = encrypted_by;

                                    data_store
                                        .create(
                                            &path_params.path,
                                            Data {
                                                data_type: body_params.data_type.clone(),
                                                path: path_params.path.clone(),
                                                value: body_params.data.clone(),
                                                encrypted_by: Some(
                                                    body_params.encrypted_by.clone(),
                                                ),
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
        use crate::render::{
            RenderTemplate, Rendered, Renderer, SecureTemplateValues, UnsecureTemplateValues,
        };
        use crate::storage::{DataStorer, KeyStorer};
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

        #[derive(Deserialize, Serialize, Debug)]
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
                        match query_params.index {
                            Some(index) => {
                                template_values.insert("index".to_string(), index.to_string())
                            }
                            _ => None,
                        };
                        match query_params.fetch_id {
                            Some(fetch_id) => {
                                template_values.insert("fetch_id".to_string(), fetch_id.to_string())
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

        pub fn with_token<
            S: SessionStore,
            R: Renderer,
            T: TokenGenerator,
            D: DataStorer,
            K: KeyStorer,
        >(
            session_store: S,
            render_engine: R,
            token_generator: T,
            data_store: D,
            keys_store: K,
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
                .and(warp::any().map(move || keys_store.clone()))
                .and_then(
                    move |path_params: WithTokenPathParams,
                          query_params: WithTokenQueryParams,
                          session_with_store: SessionWithStore<S>,
                          token: String,
                          render_engine: R,
                          data_store: D,
                          keys_store: K| async move {
                        //let mut template_values2 = HashMap::new();
                        let mut template_values = SecureTemplateValues::default();
                        if let Some(css) = &query_params.css {
                            template_values.css = Some(css.to_owned())
                        };
                        match &query_params.edit {
                            Some(edit) => {
                                if *edit {
                                    template_values.edit = Some(true);
                                    template_values.token = token.clone();
                                }
                            }
                            _ => (),
                        };
                        template_values.path = path_params.path.clone();

                        match session_with_store.session.get("token") {
                            Some::<String>(session_token) => {
                                if session_token != path_params.token {
                                    template_values.data = "".to_owned();
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
                                    let is_valid_request =
                                        match (&query_params.fetch_id, query_params.index) {
                                            (Some(_fetch_id), None) => false,
                                            (None, Some(_index)) => false,
                                            _ => true,
                                        };

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
                                        (Some(_fetch_id), Some(index)) => {
                                            let (value, data_type): (String, String) = data_store
                                                .get_collection(&path_params.path, index, 1)
                                                .await
                                                .map_or_else(
                                                    |_| ("".to_owned(), "string".to_owned()),
                                                    |mut data| {
                                                        let (value, data_type) =
                                                            match data.results.pop() {
                                                                Some(s) => {
                                                                    let val_str =
                                                                        match s.value.as_str() {
                                                                            Some(s) => s.to_owned(),
                                                                            None => "".to_owned(),
                                                                        };
                                                                    let data_type = s.data_type;
                                                                    (val_str, data_type)
                                                                }
                                                                None => (
                                                                    "".to_owned(),
                                                                    "string".to_owned(),
                                                                ),
                                                            };
                                                        (value, data_type)
                                                    },
                                                );

                                            template_values.data = value;
                                            template_values.data_type = data_type;
                                        }
                                        _ => {
                                            // Non-collection request
                                            let (value, data_type): (String, String) = data_store
                                                .get(&path_params.path)
                                                .await
                                                .map_or_else(
                                                    |e| ("".to_owned(), "string".to_owned()),
                                                    |data| {
                                                        let val_str = match data.value.as_str() {
                                                            Some(s) => s.to_owned(),
                                                            None => "".to_owned(),
                                                        };
                                                        (val_str, data.data_type)
                                                    },
                                                );
                                            template_values.data = value;
                                            template_values.data_type = data_type;
                                        }
                                    }

                                    let mut encrypted_by = None;
                                    if let Some(edit) = query_params.edit {
                                        if edit {
                                            if let Ok(keys) = keys_store.list().await {
                                                encrypted_by = Some(
                                                    keys.results
                                                        .iter()
                                                        .map(|key| key.name().to_owned())
                                                        .collect(),
                                                );
                                            }
                                        }
                                    }
                                    template_values.encrypted_by = encrypted_by;

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
                                template_values.data = "".to_string();
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
mod tests {
    mod get {
        mod with_token {
            use crate::render::{tests::MockRenderer, RenderTemplate};
            use crate::routes::data::get;
            use crate::storage::{tests::MockStorer, Data};
            use crate::token::tests::MockTokenGenerator;
            use async_trait::async_trait;
            use mockall::predicate::*;
            use mockall::*;
            use serde::Serialize;
            use serde_json::json;

            use std::{
                collections::HashMap,
                fmt::{self, Debug, Formatter},
                sync::Arc,
            };
            use warp_sessions::{ArcSessionStore, Session, SessionStore};

            mock! {
                        pub SessionStore {}

            #[async_trait]
            impl SessionStore for SessionStore {
                        async fn load_session(&self, cookie_value: String) -> async_session::Result<Option<Session>>;
                        async fn store_session(&self, session: Session) -> async_session::Result<Option<String>>;
                        async fn destroy_session(&self, session: Session) -> async_session::Result;
                        async fn clear_store(&self) -> async_session::Result;
                    }

                                impl Debug for SessionStore {
                                    fn fmt<'a>(&self, f: &mut Formatter<'a>) -> fmt::Result;
                                }

                                impl Clone for SessionStore {
                                    fn clone(&self) -> Self;
                                }
                                }

            mock! {
                pub Session {
                    fn new() -> Self;
                            fn id_from_cookie_value(string: &str) -> Result<String, base64::DecodeError>;
                            fn destroy(&mut self);
                            fn is_destroyed(&self) -> bool;
                    fn id(&self) -> &str;
                    fn insert<T: Serialize +'static>(&mut self, key: &str, value: T) -> Result<(), serde_json::Error>;
                    fn insert_raw(&mut self, key: &str, value: String);
                    fn get<T: serde::de::DeserializeOwned + 'static>(&self, key: &str) -> Option<T>;
                    fn get_raw(&self, key: &str) -> Option<String>;
                }
            impl Clone for Session {
                fn clone(&self) -> Self;
            }
                impl Debug for Session {
                    fn fmt<'a>(&self, f: &mut Formatter<'a>) -> fmt::Result;
                }
            }

            #[tokio::test]
            async fn with_token_with_no_query_params() {
                let mut session = Session::new();
                session.set_cookie_value("testSID".to_owned());
                session
                    .insert(
                        "token",
                        "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C",
                    )
                    .unwrap();
                let expected_sid = session.id().to_owned();

                let mut mock_store = MockSessionStore::new();
                mock_store
                    .expect_load_session()
                    .with(predicate::eq("testSID".to_owned()))
                    .times(1)
                    .return_once(move |_| Ok(Some(session)));
                mock_store
                    .expect_destroy_session()
                    .withf(move |session: &Session| session.id() == expected_sid)
                    .times(1)
                    .return_once(move |_| Ok(()));
                let session_store = ArcSessionStore(Arc::new(mock_store));

                let mut render_engine = MockRenderer::new();
                render_engine
                    .expect_render()
                    .withf(move |template: &RenderTemplate<HashMap<String, String>>| {
                        let mut expected_value = HashMap::new();
                        expected_value.insert("path".to_string(), ".testKey.".to_string());
                        expected_value.insert("data".to_owned(), "testValue".to_owned());
                        expected_value.insert("data_type".to_owned(), "string".to_owned());
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

                let mut storer = MockStorer::new();
                storer
                    .expect_get()
                    .times(1)
                    .with(predicate::eq(".testKey."))
                    .returning(|_| {
                        Ok(Data {
                            data_type: "string".to_owned(),
                            path: ".testKey.".to_owned(),
                            value: json!("testValue"),
                        })
                    });

                let with_token_filter = get::with_token(
                    session_store,
                    Arc::new(render_engine),
                    Arc::new(token_generator),
                    Arc::new(storer),
                );

                let res = warp::test::request()
                    .method("POST")
                    .path("/data/.testKey./E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C")
                    .header("cookie", "sid=testSID")
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
