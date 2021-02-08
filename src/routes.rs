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
        use crate::redis_client::FetchCacher;

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

        pub fn with_token<S: SessionStore, R: Renderer, T: TokenGenerator, D: Storer, F: FetchCacher>(
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

                                            match redis_client.exists_index(fetch_id, index).await.unwrap() {
                                                true => {
                                                    let (value, data_type): (String, String) = redis_client.get_index(fetch_id, index).await.map_or_else(
                                                        |_e| ("".to_string(), "string".to_string()),
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
                                                    let page_size = redis_client.get_collection_size();
                                                    let page_number = index / i64::from(page_size);

                                                    let (value, data_type): (String, String) =
                                                        match data_store.get_collection(&path_params.path, page_number * i64::from(page_size)).await {
                                                            Ok(data) => {
                                                                match redis_client.set(fetch_id, page_number,&data.results.clone(), 60).await {
                                                                    Ok(()) => { },
                                                                    Err(err) => eprintln!("Error: {:?}", err)
                                                                }

                                                                let page_index = (index % i64::from(page_size)) as usize;
                                                                match page_index >= data.results.len() {
                                                                    true => ("".to_string(), "string".to_string()),
                                                                    false => {
                                                                        let result_at_index = data.results[page_index].clone();
                                                                        let val_str = match result_at_index.value.as_str() {
                                                                            Some(s) => s.to_owned(),
                                                                            None => "".to_string(),
                                                                        };
                                                                        (val_str, result_at_index.data_type)
                                                                    }
                                                                }


                                                            },
                                                            Err(_e) => ("".to_string(), "string".to_string())
                                                        };

                                                    template_values.insert("data".to_string(), value);
                                                    template_values.insert("data_type".to_string(), data_type);
                                                }
                                            }



                                        },
                                        _ => {
                                            // Non-collection request
                                            let (value, data_type): (String, String) = data_store
                                                .get(&path_params.path)
                                                .await
                                                .map_or_else(
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
                                            template_values
                                                .insert("data_type".to_string(), data_type);
                                        }
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

#[cfg(test)]
mod tests {
    mod get {
        mod with_token {
            use crate::render::{tests::MockRenderer, RenderTemplate};
            use crate::routes::data::get;
            use crate::storage::{tests::MockStorer, Data, DataCollection};
            use crate::token::tests::MockTokenGenerator;
            use crate::redis_client::tests::MockFetchCacher;
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

                let mut fetch_cacher = MockFetchCacher::new();
                fetch_cacher
                    .expect_exists_index()
                    .times(0);

                let with_token_filter = get::with_token(
                    session_store,
                    Arc::new(render_engine),
                    Arc::new(token_generator),
                    Arc::new(storer),
                    Arc::new(fetch_cacher),
                );

                let res = warp::test::request()
                    .method("POST")
                    .path("/data/.testKey./E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C")
                    .header("cookie", "sid=testSID")
                    .reply(&with_token_filter)
                    .await;
                assert_eq!(res.status(), 200);
            }

            #[tokio::test]
            async fn with_token_collection_not_cached() {
                let mut session = Session::new();
                session.set_cookie_value("testSID".to_owned());
                session.insert("token","TOKEN").unwrap();

                let mut mock_store = MockSessionStore::new();
                mock_store.expect_load_session().return_once(move |_| Ok(Some(session)));
                mock_store.expect_destroy_session().return_once(move |_| Ok(()));

                let session_store = ArcSessionStore(Arc::new(mock_store));

                let mut render_engine = MockRenderer::new();
                render_engine.expect_render().return_once(move |_| Ok("".to_string()));

                let mut token_generator = MockTokenGenerator::new();
                token_generator.expect_generate_token().returning(|| Ok("".to_owned()));

                let mut fetch_cacher = MockFetchCacher::new();
                fetch_cacher.expect_exists_index().times(1).returning(|_, _| Ok(false));
                fetch_cacher.expect_get_collection_size().times(1).returning(|| 10);
                fetch_cacher
                    .expect_set()
                    .times(1)
                    // TODO: add argument matchers
                    .returning(|_,_,_,_| Ok(()));

                let mut storer = MockStorer::new();
                storer
                    .expect_get_collection()
                    .times(1)
                    .returning(|_, _| {
                        Ok(DataCollection {
                            results: vec![
                                Data {
                                    data_type: "string".to_owned(),
                                    path: ".testKey.".to_owned(),
                                    value: json!("testValue"),
                                }
                            ]
                        })
                    });

                let with_token_filter = get::with_token(
                    session_store,
                    Arc::new(render_engine),
                    Arc::new(token_generator),
                    Arc::new(storer),
                    Arc::new(fetch_cacher),
                );

                let res = warp::test::request()
                    .method("POST")
                    .path("/data/.testKey./TOKEN?index=0&fetch_id=abc")
                    .header("cookie", "sid=testSID")
                    .reply(&with_token_filter)
                    .await;
                assert_eq!(res.status(), 200);
            }

            #[tokio::test]
            async fn with_token_collection_cached() {
                let mut session = Session::new();
                session.set_cookie_value("testSID".to_owned());
                session.insert("token","TOKEN").unwrap();

                let mut mock_store = MockSessionStore::new();
                mock_store.expect_load_session().return_once(move |_| Ok(Some(session)));
                mock_store.expect_destroy_session().return_once(move |_| Ok(()));

                let session_store = ArcSessionStore(Arc::new(mock_store));

                let mut render_engine = MockRenderer::new();
                render_engine.expect_render().return_once(move |_| Ok("".to_string()));

                let mut token_generator = MockTokenGenerator::new();
                token_generator.expect_generate_token().returning(|| Ok("".to_owned()));

                let mut fetch_cacher = MockFetchCacher::new();
                fetch_cacher.expect_exists_index().times(1).returning(|_, _| Ok(true));
                fetch_cacher.expect_set().times(0);
                fetch_cacher.expect_get_index()
                    .times(1)
                    .with(predicate::eq("abc"), predicate::eq(0))
                    .returning(|_,_| {
                        Ok(Data {
                            data_type: "string".to_owned(),
                            path: ".testKey.".to_owned(),
                            value: json!("testValue"),
                        })
                    });

                let mut storer = MockStorer::new();
                storer.expect_get_collection().times(0);

                let with_token_filter = get::with_token(
                    session_store,
                    Arc::new(render_engine),
                    Arc::new(token_generator),
                    Arc::new(storer),
                    Arc::new(fetch_cacher),
                );

                let res = warp::test::request()
                    .method("POST")
                    .path("/data/.testKey./TOKEN?index=0&fetch_id=abc")
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
