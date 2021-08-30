use crate::routes::error::QueryParamValidationRejection;
use crate::{
    render::{
        RenderTemplate, Rendered, Renderer, SecureTemplateValues, TemplateValues,
        UnsecureTemplateValues,
    },
    routes::{
        CryptoErrorRejection, IframeTokensDoNotMatchRejection, SessionTokenNotFoundRejection,
    },
    token::TokenGenerator,
};
use percent_encoding::percent_decode_str;
use redact_crypto::{CryptoError, Data, Storer};
use regex::Regex;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use warp::{Filter, Rejection, Reply};
use warp_sessions::{
    self, CookieOptions, SameSiteCookieOption, Session, SessionStore, SessionWithStore,
};

pub trait Validate {
    fn validate(&self) -> Result<(), Rejection>;
}

#[derive(Deserialize, Serialize)]
struct WithoutTokenQueryParams {
    css: Option<String>,
    edit: Option<bool>,
    data_type: Option<String>,
    relay_url: Option<String>,
    js_message: Option<String>,
    js_height_msg_prefix: Option<String>
}

impl Validate for WithoutTokenQueryParams {
    fn validate(&self) -> Result<(), Rejection> {
        validate_base64_query_param(self.js_message.clone())?;
        validate_base64_query_param(self.js_height_msg_prefix.clone())?;
        Ok::<_, Rejection>(())
    }
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
    js_message: Option<String>,
    js_height_msg_prefix: Option<String>
}

impl Validate for WithTokenQueryParams {
    fn validate(&self) -> Result<(), Rejection> {
        validate_base64_query_param(self.js_message.clone())?;
        validate_base64_query_param(self.js_height_msg_prefix.clone())?;
        Ok::<_, Rejection>(())
    }
}

#[derive(Deserialize, Serialize, Debug)]
struct WithTokenPathParams {
    path: String,
    token: String,
}

pub fn validated_query_params<T: 'static + DeserializeOwned + Send + Validate>(
) -> impl Filter<Extract = (T,), Error = Rejection> + Copy {
    warp::query::<T>().and_then(move |param: T| async move {
        param.validate()?;
        Ok::<_, Rejection>(param)
    })
}

pub fn without_token<S: SessionStore, R: Renderer, T: TokenGenerator>(
    session_store: S,
    render_engine: R,
    token_generator: T,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::any()
        .and(warp::path!("data" / String).map(|path| WithoutTokenPathParams { path }))
        .and(validated_query_params::<WithoutTokenQueryParams>())
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
                let utv = UnsecureTemplateValues {
                    path: path_params.path.clone(),
                    token: token.clone(),
                    css: query_params.css,
                    edit: query_params.edit,
                    data_type: query_params.data_type,
                    relay_url: query_params.relay_url,
                    js_height_msg_prefix: query_params.js_height_msg_prefix,
                    js_message: query_params.js_message,
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

pub fn with_token<S: SessionStore, R: Renderer, T: TokenGenerator, H: Storer + Clone>(
    session_store: S,
    render_engine: R,
    token_generator: T,
    storer: H,
    code_phrase: String,
    code_color: String
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
        .and(warp::any().map(move || code_phrase.clone()))
        .and(warp::any().map(move || code_color.clone()))
        .and_then(
            move |path_params: WithTokenPathParams,
                  query_params: WithTokenQueryParams,
                  session_with_store: SessionWithStore<S>,
                  token: String,
                  render_engine: R,
                  storer: H,
                  code_phrase,
                  code_color| async move {
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
                        CryptoError::NotFound { .. } => Ok(None),
                        _ => Err(e),
                    },
                }
                .map_err(CryptoErrorRejection)?;

                let data = match data_entry {
                    Some(data_entry) => data_entry
                        .take_resolve()
                        .await
                        .map_err(CryptoErrorRejection)?,
                    None => {
                        if let Some(data_type) = query_params.data_type.clone() {
                            match data_type.to_ascii_lowercase().as_ref() {
                                "bool" => Data::Bool(false),
                                "u64" => Data::U64(0),
                                "i64" => Data::I64(0),
                                "f64" => Data::F64(0.0),
                                "media" => Data::Binary(None),
                                _ => Data::String("".to_owned()),
                            }
                        } else {
                            Data::String("".to_owned())
                        }
                    }
                };

                let is_binary_data = match data {
                    Data::Binary(_) => true,
                    _ => query_params.data_type == Some("media".to_owned())
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
                            data_type: query_params.data_type,
                            relay_url: query_params.relay_url,
                            js_message: query_params.js_message,
                            js_height_msg_prefix: query_params.js_height_msg_prefix,
                            is_binary_data: is_binary_data,
                            code_phrase,
                            code_color
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

fn validate_base64_query_param(str: Option<String>) -> Result<(), Rejection> {
    match str {
        Some(msg) => percent_decode_str(&msg)
            .decode_utf8()
            .map_err(|_| warp::reject::custom(QueryParamValidationRejection))
            .and_then(|str| {
                let base64_regex = Regex::new(r"^[A-Za-z0-9+/]+={0,2}$").unwrap();
                match base64_regex.is_match(&str.to_string()) {
                    true => Ok::<_, Rejection>(()),
                    false => Err(warp::reject::custom(QueryParamValidationRejection)),
                }
            }),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use mockall::predicate::*;
    use mockall::*;
    use mongodb::bson::Document;
    use redact_crypto::{CryptoError, Entry, EntryPath, HasBuilder, State, Storer, StorableType};
    use crate::token::tests::MockTokenGenerator;

    mock! {
    pub Storer {}
    #[async_trait]
    impl Storer for Storer {
    async fn get_indexed<T: StorableType>(
        &self,
        path: &str,
        index: &Option<Document>,
    ) -> Result<Entry<T>, CryptoError>;
    async fn list_indexed<T: StorableType>(
        &self,
        path: &str,
        skip: i64,
        page_size: i64,
        index: &Option<Document>,
    ) -> Result<Vec<Entry<T>>, CryptoError>;
    async fn create<T: StorableType>(&self, value: Entry<T>) -> Result<Entry<T>, CryptoError>;
    }
    impl Clone for Storer {
        fn clone(&self) -> Self;
    }
    }

    mod with_token {
        use super::MockStorer;
        use crate::render::{
            tests::MockRenderer, RenderTemplate, SecureTemplateValues, TemplateValues,
        };
        use crate::routes::data::get;
        use crate::token::tests::MockTokenGenerator;
        use async_trait::async_trait;
        use mockall::predicate::*;
        use mockall::*;
        use redact_crypto::{ByteSource, CryptoError, Data, DataBuilder, Entry, HasIndex, MongoStorerError, State, StringDataBuilder, TypeBuilder, VectorByteSource, BinaryDataBuilder, BinaryData, BinaryType};
        use serde::Serialize;

        use std::{
            fmt::{self, Debug, Formatter},
            sync::Arc,
        };
        use warp_sessions::{ArcSessionStore, Session, SessionStore};
        use crate::routes::data::get::tests::setup_mock_token_helper;

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
            let session = setup_session_helper("E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9D");
            let expected_sid = session.id().to_owned();

            let mock_store = setup_mock_session_store_helper(expected_sid, session);
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
                        data_type: None,
                        relay_url: None,
                        js_message: None,
                        js_height_msg_prefix: None,
                        is_binary_data: false
                    });
                    template.value == expected_value
                })
                .times(1)
                .return_once(move |_| Ok("".to_string()));

            let token_generator = setup_mock_token_helper(
                "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9D".to_owned(),
            );

            let mut storer = MockStorer::new();
            storer
                .expect_get_indexed::<Data>()
                .times(1)
                .withf(|path, index| {
                    path == ".testKey." && *index == Some(Data::get_index().unwrap())
                })
                .returning(|_, _| {
                    let builder = TypeBuilder::Data(DataBuilder::String(StringDataBuilder {}));
                    Ok(Entry::new(
                        ".testKey.".to_owned(),
                        builder,
                        State::Unsealed {
                            bytes: ByteSource::Vector(VectorByteSource::new(Some(b"someval"))),
                        }
                    ))
                });

            let with_token_filter = get::with_token(
                session_store,
                Arc::new(render_engine),
                Arc::new(token_generator),
                Arc::new(storer),
            );

            let res = warp::test::request()
                    .path("/data/.testKey./E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9D")
                    .header("cookie", "sid=testSID")
                    .reply(&with_token_filter)
                    .await;
            assert_eq!(res.status(), 200);
        }

        #[tokio::test]
        async fn with_token_with_data_type_binary() {
            let session = setup_session_helper("E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C");
            let expected_sid = session.id().to_owned();
            let mock_store = setup_mock_session_store_helper(expected_sid, session);
            let session_store = ArcSessionStore(Arc::new(mock_store));

            let mut render_engine = MockRenderer::new();
            render_engine
                .expect_render()
                .withf(move |template: &RenderTemplate| {
                    let expected_value = TemplateValues::Secure(SecureTemplateValues {
                        data: Some(Data::Binary(None)),
                        path: Some(".testKey.".to_owned()),
                        token: Some(
                            "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9D"
                                .to_owned(),
                        ),
                        css: None,
                        edit: None,
                        data_type: Some("Media".to_owned()),
                        relay_url: None,
                        js_message: None,
                        js_height_msg_prefix: None,
                        is_binary_data: true
                    });
                    template.value == expected_value
                })
                .times(1)
                .return_once(move |_| Ok("".to_string()));

            let token_generator = setup_mock_token_helper(
                "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9D".to_owned(),
            );

            let mut storer = MockStorer::new();
            storer
                .expect_get_indexed::<Data>()
                .times(1)
                .withf(|path, index| {
                    path == ".testKey." && *index == Some(Data::get_index().unwrap())
                })
                .returning(|_, _| {
                    Err(CryptoError::NotFound {
                        source: Box::new(CryptoError::NotDowncastable)
                    })
                });

            let with_token_filter = get::with_token(
                session_store,
                Arc::new(render_engine),
                Arc::new(token_generator),
                Arc::new(storer),
            );

            let res = warp::test::request()
                .path("/data/.testKey./E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C?data_type=Media")
                .header("cookie", "sid=testSID")
                .reply(&with_token_filter)
                .await;
            assert_eq!(res.status(), 200);
        }

        #[tokio::test]
        async fn with_token_with_existing_binary_data() {
            let session = setup_session_helper("E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C");
            let expected_sid = session.id().to_owned();

            let mock_store = setup_mock_session_store_helper(expected_sid, session);
            let session_store = ArcSessionStore(Arc::new(mock_store));

            let mut render_engine = MockRenderer::new();
            render_engine
                .expect_render()
                .withf(move |template: &RenderTemplate| {
                    let expected_value = TemplateValues::Secure(SecureTemplateValues {
                        data: Some(Data::Binary(Some(BinaryData {
                            binary_type: BinaryType::ImageJPEG,
                            binary: "abc".to_owned()
                        }))),
                        path: Some(".testKey.".to_owned()),
                        token: Some(
                            "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C"
                                .to_owned(),
                        ),
                        css: None,
                        edit: None,
                        data_type: None,
                        relay_url: None,
                        js_message: None,
                        js_height_msg_prefix: None,
                        is_binary_data: true
                    });
                    template.value == expected_value
                })
                .times(1)
                .return_once(move |_| Ok("".to_string()));

            let token_generator = setup_mock_token_helper(
                "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C".to_owned(),
            );

            let mut storer = MockStorer::new();
            storer
                .expect_get_indexed::<Data>()
                .times(1)
                .withf(|path, index| {
                    path == ".testKey." && *index == Some(Data::get_index().unwrap())
                })
                .returning(|_, _| {
                    let builder = TypeBuilder::Data(DataBuilder::Binary(BinaryDataBuilder {}));
                    Ok(Entry::new(
                        ".testKey.".to_owned(),
                        builder,
                        State::Unsealed {
                            bytes: ByteSource::Vector(VectorByteSource::new(Some(b"{\"binary\":\"abc\",\"binary_type\":\"ImageJPEG\"}"))),
                        }
                    ))
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
            let session = setup_session_helper("E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C");
            let expected_sid = session.id().to_owned();

            let mut mock_store = setup_mock_session_store_helper(expected_sid, session);
            mock_store
                .expect_store_session()
                .times(1)
                .return_once(move |_| Ok(Some("E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C".to_owned())));
            let session_store = ArcSessionStore(Arc::new(mock_store));

            let mut render_engine = MockRenderer::new();
            render_engine
                .expect_render()
                .times(1)
                .return_once(move |_| Ok("".to_string()));

            let token_generator = setup_mock_token_helper(
                "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C".to_owned(),
            );

            let mut storer = MockStorer::new();
            storer
                .expect_get_indexed::<Data>()
                .times(1)
                .withf(|path, index| {
                    path == ".testKey." && *index == Some(Data::get_index().unwrap())
                })
                .returning(|_, _| {
                    Err(CryptoError::NotFound {
                        source: Box::new(MongoStorerError::NotFound),
                    })
                });

            let with_token_filter = get::with_token(
                session_store,
                Arc::new(render_engine),
                Arc::new(token_generator),
                Arc::new(storer),
            );

            let res = warp::test::request()
                .path("/data/.testKey./E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C?edit=true&data_type=String")
                .header("cookie", "sid=testSID")
                .reply(&with_token_filter)
                .await;
            assert_eq!(res.status(), 200);
        }

        // Helper method for creating a Session with a given token
        fn setup_session_helper(token: &str) -> Session {
            let mut session = Session::new();
            session.set_cookie_value("testSID".to_owned());
            session
                .insert("token", token)
                .unwrap();
            session
        }

        // Helper method to setup the mock session store and the load & destroy session method mocks
        fn setup_mock_session_store_helper(expected_sid: String, session: Session) -> MockSessionStore {
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
        use crate::routes::data::get::tests::setup_mock_token_helper;

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
                        js_message: None,
                        js_height_msg_prefix: None,
                    });

                    template.value == expected_value
                })
                .times(1)
                .return_once(move |_| Ok("".to_string()));
            let token_generator = setup_mock_token_helper(
                "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C".to_owned()
            );

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
                        js_message: None,
                        js_height_msg_prefix: None,
                    });

                    template.value == expected_value
                })
                .times(1)
                .return_once(move |_| Ok("".to_string()));
            let token_generator = setup_mock_token_helper(
                "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C".to_owned(),
            );

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
                        js_message: None,
                        js_height_msg_prefix: None,
                    });
                    template.value == expected_value
                })
                .times(1)
                .return_once(move |_| Ok("".to_string()));
            let token_generator = setup_mock_token_helper("E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C".to_owned());

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
                        js_message: None,
                        js_height_msg_prefix: None,
                    });
                    template.value == expected_value
                })
                .times(1)
                .return_once(move |_| Ok("".to_string()));

            let token_generator = setup_mock_token_helper("E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C".to_owned());

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
                        js_message: Some(js_message.to_owned()),
                        js_height_msg_prefix: None,
                    });
                    template.value == expected_value
                })
                .times(1)
                .return_once(move |_| Ok("".to_string()));

            let token_generator = setup_mock_token_helper("E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9C".to_owned());

            let without_token_filter = get::without_token(
                session_store,
                Arc::new(render_engine),
                Arc::new(token_generator),
            );

            let res = warp::test::request()
                .path(&format!(
                    "/data/.testKey.?edit=false&js_message={}",
                    js_message
                ))
                .reply(&without_token_filter)
                .await;
            assert_eq!(res.status(), 200);
        }

        #[tokio::test]
        async fn test_without_token_with_js_message_invalid() {
            let js_message = "invalid%5C%22%29%3B+mesaage%7D%7B";

            let session_store = MemoryStore::new();
            let mut render_engine = MockRenderer::new();
            render_engine.expect_render().times(0);

            let mut token_generator = MockTokenGenerator::new();
            token_generator.expect_generate_token().times(0);

            let without_token_filter = get::without_token(
                session_store,
                Arc::new(render_engine),
                Arc::new(token_generator),
            );

            let res = warp::test::request()
                .path(&format!(
                    "/data/.testKey.?edit=false&js_message={}",
                    js_message
                ))
                .reply(&without_token_filter)
                .await;
            assert_eq!(res.status(), 500);
        }

        #[tokio::test]
        async fn test_without_token_with_js_height_msg_prefix_invalid() {
            let js_height_msg_prefix = "invalid%5C%22%29%3B+mesaage%7D%7B";

            let session_store = MemoryStore::new();
            let mut render_engine = MockRenderer::new();
            render_engine
                .expect_render()
                .times(0);

            let mut token_generator = MockTokenGenerator::new();
            token_generator
                .expect_generate_token()
                .times(0);

            let without_token_filter = get::without_token(
                session_store,
                Arc::new(render_engine),
                Arc::new(token_generator),
            );

            let res = warp::test::request()
                .path(&format!("/data/.testKey.?edit=false&js_height_msg_prefix={}", js_height_msg_prefix))
                .reply(&without_token_filter)
                .await;
            assert_eq!(res.status(), 500);
        }


    }

    // Helper method which sets up a mock TokenGenerator which returns a given token on generate_token()
    fn setup_mock_token_helper(token: String) -> MockTokenGenerator {
        let mut token_generator = MockTokenGenerator::new();
        token_generator
            .expect_generate_token()
            .times(1)
            .returning(move || Ok(token.to_owned()));
        token_generator
    }
}
