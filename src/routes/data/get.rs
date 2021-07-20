use crate::{
    render::{
        RenderTemplate, Rendered, Renderer, SecureTemplateValues, TemplateValues,
        UnsecureTemplateValues,
    },
    routes::{
        IframeTokensDoNotMatchRejection, SessionTokenNotFoundRejection, StorageErrorRejection,
    },
    token::TokenGenerator,
};
use redact_crypto::{Data, StorageError, Storer};
use serde::{Deserialize, Serialize};
use warp::{Filter, Rejection, Reply};
use warp_sessions::{
    self, CookieOptions, SameSiteCookieOption, Session, SessionStore, SessionWithStore,
};
use regex::Regex;
use percent_encoding::percent_decode_str;

#[derive(Deserialize, Serialize)]
struct WithoutTokenQueryParams {
    css: Option<String>,
    edit: Option<bool>,
    data_type: Option<String>,
    relay_url: Option<String>,
    js_message: Option<String>
}

#[derive(Deserialize, Serialize)]
struct WithoutTokenPathParams {
    path: String,
}

#[derive(Deserialize, Serialize)]
struct WithTokenQueryParams {
    css: Option<String>,
    edit: Option<bool>,
    data_type: Option<String>,
    relay_url: Option<String>,
    js_message: Option<String>
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
                same_site: Some(SameSiteCookieOption::None),
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


                let sanitized_message = query_params.js_message.and_then(|message| {
                    let decoded_param = percent_decode_str(&message.clone())
                        .decode_utf8()
                        .unwrap_or_default()
                        .to_string();
                    let base64_regex = Regex::new(r"^[A-Za-z0-9+/]+={0,2}$").unwrap();
                    match base64_regex.is_match(&decoded_param) {
                        true => Some(message),
                        false => None
                    }
                });

                let utv = UnsecureTemplateValues {
                    path: path_params.path.clone(),
                    token: token.clone(),
                    css: query_params.css,
                    edit: query_params.edit,
                    data_type: query_params.data_type,
                    relay_url: query_params.relay_url,
                    js_message: sanitized_message,
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

pub fn with_token<S: SessionStore, R: Renderer, T: TokenGenerator, H: Storer>(
    session_store: S,
    render_engine: R,
    token_generator: T,
    storer: H,
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
                same_site: Some(SameSiteCookieOption::None),
            }),
        ))
        .and(warp::any().map(move || token_generator.clone().generate_token().unwrap()))
        .and(warp::any().map(move || render_engine.clone()))
        .and(warp::any().map(move || storer.clone()))
        .and_then(
            move |path_params: WithTokenPathParams,
                  query_params: WithTokenQueryParams,
                  session_with_store: SessionWithStore<S>,
                  token: String,
                  render_engine: R,
                  storer: H| async move {
                if let Some(session_token) = session_with_store.session.get::<String>("token") {
                    if session_token != path_params.token {
                        Err(warp::reject::custom(IframeTokensDoNotMatchRejection))
                    } else {
                        Ok(())
                    }
                } else {
                    Err(warp::reject::custom(SessionTokenNotFoundRejection))
                }?;

                let data_entry = match storer.get::<Data>(&path_params.path).await {
                    Ok(e) => Ok(Some(e)),
                    Err(e) => match e {
                        StorageError::NotFound => Ok(None),
                        _ => Err(e),
                    },
                }
                .map_err(StorageErrorRejection)?;

                let data = match data_entry {
                    Some(data_entry) => storer
                        .resolve::<Data>(data_entry.value)
                        .await
                        .map_err(StorageErrorRejection)?,
                    None => {
                        if let Some(data_type) = query_params.data_type {
                            match data_type.to_ascii_lowercase().as_ref() {
                                "bool" => Data::Bool(false),
                                "u64" => Data::U64(0),
                                "i64" => Data::I64(0),
                                "f64" => Data::F64(0.0),
                                _ => Data::String("".to_owned()),
                            }
                        } else {
                            Data::String("".to_owned())
                        }
                    }
                };
                let reply = Rendered::new(
                    render_engine,
                    RenderTemplate {
                        name: "secure",
                        value: TemplateValues::Secure(SecureTemplateValues {
                            data: Some(data),
                            path: Some(path_params.path.clone()),
                            token: Some(token.clone()),
                            css: query_params.css,
                            edit: query_params.edit,
                            relay_url: query_params.relay_url,
                            js_message: query_params.js_message,
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
                        same_site: Some(SameSiteCookieOption::None),
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
        use redact_crypto::{
            storage::tests::MockStorer, ByteSource, Data, DataBuilder, Entry, HasIndex, States,
            StorageError, StringDataBuilder, TypeBuilder, VectorByteSource,
        };
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
                        data: Some(Data::String("someval".into())),
                        path: Some(".testKey.".to_owned()),
                        token: Some(
                            "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9D"
                                .to_owned(),
                        ),
                        css: None,
                        edit: None,
                        relay_url: None,
                        js_message: None,
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

            let mut storer = MockStorer::new();
            storer
                .expect_get_indexed::<Data>()
                .times(1)
                .withf(|path, index| {
                    path == ".testKey." && *index == Some(Data::get_index().unwrap())
                })
                .returning(|_, _| {
                    let builder = TypeBuilder::Data(DataBuilder::String(StringDataBuilder {}));
                    Ok(Entry {
                        path: ".testKey.".to_owned(),
                        value: States::Unsealed {
                            builder,
                            bytes: ByteSource::Vector(VectorByteSource::new(b"someval")),
                        },
                    })
                });

            let with_token_filter = get::with_token(
                session_store,
                Arc::new(render_engine),
                Arc::new(token_generator),
                Arc::new(storer),
            );

            let res = warp::test::request()
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

            let mut storer = MockStorer::new();
            storer
                .expect_get_indexed::<Data>()
                .times(1)
                .withf(|path, index| {
                    path == ".testKey." && *index == Some(Data::get_index().unwrap())
                })
                .returning(|_, _| Err(StorageError::NotFound));

            let with_token_filter = get::with_token(
                session_store,
                Arc::new(render_engine),
                Arc::new(token_generator),
                Arc::new(storer),
            );

            let res = warp::test::request()
                .path("/data/.testKey./E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C?create=true&data_type=String")
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
                        data_type: None,
                        relay_url: None,
                        js_message: None
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
                        data_type: None,
                        relay_url: None,
                        js_message: None
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
                        data_type: None,
                        relay_url: None,
                        js_message: None
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
                        data_type: None,
                        relay_url: None,
                        js_message: None
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


        #[tokio::test]
        async fn test_without_token_with_js_message_valid() {
            let js_message = "dXBkYXRl";

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
                        data_type: None,
                        relay_url: None,
                        js_message: Some(js_message.to_owned())
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
                .path(&format!("/data/.testKey.?edit=false&js_message={}", js_message))
                .reply(&without_token_filter)
                .await;
            assert_eq!(res.status(), 200);
        }

        #[tokio::test]
        async fn test_without_token_with_js_message_invalid() {
            let js_message = "invalid%5C%22%29%3B+mesaage%7D%7B";

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
                        data_type: None,
                        relay_url: None,
                        js_message: None
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
                .path(&format!("/data/.testKey.?edit=false&js_message={}", js_message))
                .reply(&without_token_filter)
                .await;
            assert_eq!(res.status(), 200);
        }
    }
}
