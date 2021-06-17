use crate::{
    render::{
        RenderTemplate, Rendered, Renderer, SecureTemplateValues, TemplateValues,
        UnsecureTemplateValues,
    },
    routes::{
        DataStorageErrorRejection, IframeTokensDoNotMatchRejection, SessionTokenNotFoundRejection,
    },
    token::TokenGenerator,
};
use redact_crypto::KeyStorer;
use redact_data::{DataStorer, Data, DataValue, DataType, UnencryptedDataValue};
use serde::{Deserialize, Serialize};
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
    create: Option<bool>,
    create_data_type: Option<DataType>
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
    create: Option<bool>,
    create_data_type: Option<DataType>
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
                let utv = UnsecureTemplateValues {
                    path: path_params.path.clone(),
                    token: token.clone(),
                    css: query_params.css,
                    edit: query_params.edit,
                    index: query_params.index,
                    fetch_id: query_params.fetch_id,
                    create: query_params.create,
                    create_data_type: query_params.create_data_type,
                };
                Ok::<_, Rejection>((
                    Rendered::new(
                        render_engine,
                        RenderTemplate {
                            name: "unsecure",
                            value: TemplateValues::Unsecure(utv),
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
                session_with_store.cookie_options.path =
                    Some(format!("/data/{}/{}", path_params.path, token));

                Ok::<_, Rejection>((reply, session_with_store))
            },
        )
        .untuple_one()
        .and_then(warp_sessions::reply::with_session)
}

pub fn with_token<S: SessionStore, R: Renderer, T: TokenGenerator, D: DataStorer, K: KeyStorer>(
    session_store: S,
    render_engine: R,
    token_generator: T,
    data_store: D,
    key_store: K,
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
        .and(warp::any().map(move || key_store.clone()))
        .and_then(
            move |path_params: WithTokenPathParams,
                  query_params: WithTokenQueryParams,
                  session_with_store: SessionWithStore<S>,
                  token: String,
                  render_engine: R,
                  data_store: D,
                  key_store: K| async move {
                if let Some(session_token) = session_with_store.session.get::<String>("token") {
                    if session_token != path_params.token {
                        Err(warp::reject::custom(IframeTokensDoNotMatchRejection))
                    } else {
                        Ok(())
                    }
                } else {
                    Err(warp::reject::custom(SessionTokenNotFoundRejection))
                }?;

                if let (Some(_fetch_id), Some(index)) = (query_params.fetch_id.clone(), query_params.index.clone())
                {
                    let mut data_collection = data_store
                        .get_collection(&path_params.path, index, 1)
                        .await
                        .map_err(|e| warp::reject::custom(DataStorageErrorRejection(e)))?;
                    if let Some(data) = data_collection.0.pop() {
                        let reply = Rendered::new(
                            render_engine,
                            RenderTemplate {
                                name: "secure",
                                value: TemplateValues::Secure(SecureTemplateValues {
                                    data: Some(data.clone()),
                                    path: Some(data.path()),
                                    token: Some(token.clone()),
                                    css: query_params.css,
                                    edit: query_params.edit,
                                }),
                            },
                        )?;

                        Ok::<_, Rejection>((
                            reply,
                            path_params,
                            query_params.edit.unwrap_or(false),
                            token,
                            session_with_store,
                        ))
                    } else {
                        Ok::<_, Rejection>((
                            Rendered::new(
                                render_engine,
                                RenderTemplate {
                                    name: "secure",
                                    value: TemplateValues::Secure(SecureTemplateValues {
                                        data: None,
                                        path: None,
                                        token: None,
                                        css: query_params.css,
                                        edit: query_params.edit,
                                    }),
                                },
                            )?,
                            path_params,
                            query_params.edit.unwrap_or(false),
                            token,
                            session_with_store,
                        ))
                    }
                } else {
                    // Non-collection request
                    let data = data_store
                        .get(&path_params.path)
                        .await
                        .or_else(|err| {
                            match query_params.create.clone() {
                                Some(create) => {
                                    // Ignore errors when creating data because non existing entries
                                    // throws erroneous errors
                                    if create {
                                        Ok(Data::new(
                                            &path_params.path,
                                            match query_params.create_data_type.clone() {
                                                Some(DataType::String) => DataValue::Unencrypted(UnencryptedDataValue::String("".to_owned())),
                                                Some(DataType::U64) => DataValue::Unencrypted(UnencryptedDataValue::U64(0)),
                                                Some(DataType::I64) => DataValue::Unencrypted(UnencryptedDataValue::I64(0)),
                                                Some(DataType::F64) => DataValue::Unencrypted(UnencryptedDataValue::F64(0.0)),
                                                Some(DataType::Bool) => DataValue::Unencrypted(UnencryptedDataValue::Bool(true)),
                                                _ => DataValue::Unencrypted(UnencryptedDataValue::String("".to_owned()))
                                            }))
                                    } else {
                                        Err(err)
                                    }
                                }
                                _ => Err(err)
                            }
                        })
                        .map_err(|e| warp::reject::custom(DataStorageErrorRejection(e)))?;
                    let reply = Rendered::new(
                        render_engine,
                        RenderTemplate {
                            name: "secure",
                            value: TemplateValues::Secure(SecureTemplateValues {
                                data: Some(data.clone()),
                                path: Some(data.path()),
                                token: Some(token.clone()),
                                css: query_params.css,
                                edit: query_params.edit.clone().or(query_params.create.clone()),
                            }),
                        },
                    )?;

                    Ok::<_, Rejection>((
                        reply,
                        path_params,
                        query_params.edit.or(query_params.create).unwrap_or(false),
                        token,
                        session_with_store,
                    ))
                }
            },
        )
        .untuple_one()
        .and_then(
            move |reply: Rendered,
                  path_params: WithTokenPathParams,
                  edit: bool,
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
                        path: Some(format!("/data/{}", token.clone())),
                        secure: false,
                        http_only: true,
                        same_site: Some(SameSiteCookieOption::Strict),
                    },
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

#[cfg(test)]
mod tests {
    mod with_token {
        use crate::render::{
            tests::MockRenderer, RenderTemplate, SecureTemplateValues, TemplateValues,
        };
        use crate::routes::data::get;
        use crate::token::tests::MockTokenGenerator;
        use async_trait::async_trait;
        use mockall::predicate::*;
        use mockall::*;
        use redact_crypto::storage::tests::MockKeyStorer;
        use redact_data::{storage::tests::MockDataStorer, Data, StorageError};
        use serde::Serialize;

        use std::{
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
                .withf(move |template: &RenderTemplate| {
                    let expected_value = TemplateValues::Secure(SecureTemplateValues {
                        data: Some(Data::new(".testKey.", "someval".into())),
                        path: Some(".testKey.".to_owned()),
                        token: Some(
                            "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9D"
                                .to_owned(),
                        ),
                        css: None,
                        edit: None,
                    });
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
                        "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9D"
                            .to_owned(),
                    )
                });

            let mut data_storer = MockDataStorer::new();
            data_storer
                .expect_get()
                .times(1)
                .with(predicate::eq(".testKey."))
                .returning(|_| Ok(Data::new(".testKey.", "someval".into())));

            let mut key_storer = MockKeyStorer::new();
            key_storer.expect_get().times(0);

            let with_token_filter = get::with_token(
                session_store,
                Arc::new(render_engine),
                Arc::new(token_generator),
                Arc::new(data_storer),
                Arc::new(key_storer),
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
        async fn with_token_create() {
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
            mock_store
                .expect_store_session()
                .times(1)
                .return_once(|_| Ok(Some("E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C".to_string())));
            let session_store = ArcSessionStore(Arc::new(mock_store));

            let mut render_engine = MockRenderer::new();
            render_engine
                .expect_render()
                .times(1)
                .return_once(move |_| Ok("".to_string()));

            let mut token_generator = MockTokenGenerator::new();
            token_generator
                .expect_generate_token()
                .times(1)
                .returning(|| {
                    Ok(
                        "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9D"
                            .to_owned(),
                    )
                });

            let mut data_storer = MockDataStorer::new();
            data_storer
                .expect_get()
                .times(1)
                .with(predicate::eq(".testKey."))
                .returning(|_| Err(StorageError::NotFound));

            let mut key_storer = MockKeyStorer::new();
            key_storer.expect_get().times(0);

            let with_token_filter = get::with_token(
                session_store,
                Arc::new(render_engine),
                Arc::new(token_generator),
                Arc::new(data_storer),
                Arc::new(key_storer),
            );

            let res = warp::test::request()
                .method("POST")
                .path("/data/.testKey./E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C?create=true&create_data_type=String")
                .header("cookie", "sid=testSID")
                .reply(&with_token_filter)
                .await;
            assert_eq!(res.status(), 200);
        }
    }

    mod without_token {
        use crate::render::{
            tests::MockRenderer, RenderTemplate, TemplateValues, UnsecureTemplateValues,
        };
        use crate::routes::data::get;
        use crate::token::tests::MockTokenGenerator;
        use std::sync::Arc;
        use warp_sessions::MemoryStore;

        #[tokio::test]
        async fn without_token_with_no_query_params() {
            let session_store = MemoryStore::new();
            let mut render_engine = MockRenderer::new();
            render_engine
                .expect_render()
                .withf(move |template: &RenderTemplate| {
                    let expected_value = TemplateValues::Unsecure(UnsecureTemplateValues {
                        path: ".testKey.".to_owned(),
                        token: "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C"
                            .to_owned(),
                        css: None,
                        edit: None,
                        index: None,
                        fetch_id: None,
                        create: None,
                        create_data_type: None
                    });

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
                .withf(move |template: &RenderTemplate| {
                    let expected_value = TemplateValues::Unsecure(UnsecureTemplateValues {
                        path: ".testKey.".to_owned(),
                        token: "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C"
                            .to_owned(),
                        css: Some("p { color: red; }".to_owned()),
                        edit: None,
                        index: None,
                        fetch_id: None,
                        create: None,
                        create_data_type: None
                    });

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
                .withf(move |template: &RenderTemplate| {
                    let expected_value = TemplateValues::Unsecure(UnsecureTemplateValues {
                        path: ".testKey.".to_owned(),
                        token: "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C"
                            .to_owned(),
                        css: None,
                        edit: Some(true),
                        index: None,
                        fetch_id: None,
                        create: None,
                        create_data_type: None
                    });
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
                .withf(move |template: &RenderTemplate| {
                    let expected_value = TemplateValues::Unsecure(UnsecureTemplateValues {
                        path: ".testKey.".to_owned(),
                        token: "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C"
                            .to_owned(),
                        css: None,
                        edit: Some(false),
                        index: None,
                        fetch_id: None,
                        create: None,
                        create_data_type: None
                    });
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
