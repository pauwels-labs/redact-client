use crate::routes::error::RelayRejection;
use crate::{
    render::{RenderTemplate, Rendered, Renderer, SecureTemplateValues, TemplateValues},
    routes::{
        BadRequestRejection, CryptoErrorRejection, IframeTokensDoNotMatchRejection,
        SerializationRejection, SessionTokenNotFoundRejection, StorageErrorRejection,
    },
    token::TokenGenerator,
};
use redact_crypto::{Data, HasBuilder, States, Storer, SymmetricKey, SymmetricSealer, TypeBuilder};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use warp::{Filter, Rejection, Reply};
use warp_sessions::{CookieOptions, SameSiteCookieOption, Session, SessionStore, SessionWithStore};
use crate::relayer::Relayer;

#[derive(Deserialize, Serialize)]
struct SubmitDataPathParams {
    token: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct SubmitDataBodyParams {
    path: String,
    value: Option<String>,
    value_type: String,
    relay_url: Option<String>,
    js_message: Option<String>
}

impl TryFrom<SubmitDataBodyParams> for Data {
    type Error = BadRequestRejection;

    fn try_from(body: SubmitDataBodyParams) -> Result<Self, Self::Error> {
        if let Some(value) = body.value {
            Ok(match body.value_type.as_ref() {
                "bool" => Data::Bool(value.parse::<bool>().or(Err(BadRequestRejection))?),
                "u64" => Data::U64(value.parse::<u64>().or(Err(BadRequestRejection))?),
                "i64" => Data::I64(value.parse::<i64>().or(Err(BadRequestRejection))?),
                "f64" => Data::F64(value.parse::<f64>().or(Err(BadRequestRejection))?),
                "string" => Data::String(value),
                _ => return Err(BadRequestRejection),
            })
        } else {
            Ok(Data::Bool(false))
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

pub fn submit_data<S: SessionStore, R: Renderer, T: TokenGenerator, H: Storer, Q: Relayer>(
    session_store: S,
    render_engine: R,
    token_generator: T,
    storer: H,
    relayer: Q
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::any()
        .and(warp::path!("data" / String).map(|token| SubmitDataPathParams { token }))
        .and(warp::query::<SubmitDataQueryParams>())
        .and(
            warp::filters::body::form::<SubmitDataBodyParams>().and_then(
                move |body: SubmitDataBodyParams| async {
                    Ok::<_, Rejection>((body.clone(), Data::try_from(body)?))
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
                same_site: Some(SameSiteCookieOption::None),
            }),
        ))
        .and(warp::any().map(move || token_generator.clone().generate_token().unwrap()))
        .and(warp::any().map(move || render_engine.clone()))
        .and(warp::any().map(move || storer.clone()))
        .and(warp::any().map(move || relayer.clone()))
        .and_then(
            move |path_params: SubmitDataPathParams,
                  query_params: SubmitDataQueryParams,
                  (body_params, data): (SubmitDataBodyParams, Data),
                  session_with_store: SessionWithStore<S>,
                  token: String,
                  render_engine: R,
                  storer: H,
                  relayer: Q| async move {
                match session_with_store.session.get("token") {
                    Some::<String>(session_token) => {
                        if session_token != path_params.token {
                            Err(warp::reject::custom(IframeTokensDoNotMatchRejection))
                        } else {
                            let key_entry = storer
                                .get::<SymmetricKey>(".keys.default")
                                .await
                                .map_err(StorageErrorRejection)?;
                            let key: SymmetricKey = storer
                                .resolve(key_entry.value.clone())
                                .await
                                .map_err(StorageErrorRejection)?;
                            let builder = TypeBuilder::Data(data.builder());
                            let unsealable = key
                                .seal(data.clone().into(), None, Some(key_entry.path))
                                .map_err(CryptoErrorRejection)?;

                            storer
                                .create(
                                    body_params.path.clone(),
                                    States::Sealed {
                                        builder,
                                        unsealable,
                                    },
                                )
                                .await
                                .map_err(StorageErrorRejection)?;

                            if let Some(relay_url) = body_params.relay_url.clone() {
                                relayer.relay(body_params.path.clone(), relay_url)
                                .await
                                .map_err(|_| warp::reject::custom(RelayRejection))?;
                            }

                            Ok::<_, Rejection>((
                                Rendered::new(
                                    render_engine,
                                    RenderTemplate {
                                        name: "secure",
                                        value: TemplateValues::Secure(SecureTemplateValues {
                                            data: Some(data),
                                            path: Some(body_params.path),
                                            token: Some(token.clone()),
                                            css: query_params.css,
                                            edit: query_params.edit,
                                            relay_url: body_params.relay_url,
                                            js_message: body_params.js_message,
                                        }),
                                    },
                                )?,
                                path_params,
                                token,
                                session_with_store,
                            ))
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
                        same_site: Some(SameSiteCookieOption::None),
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

#[cfg(test)]
mod tests {
    use crate::render::tests::MockRenderer;
    use crate::routes::data::post;
    use crate::token::tests::MockTokenGenerator;
    use crate::relayer::tests::MockRelayer;
    use async_trait::async_trait;
    use mockall::predicate::*;
    use mockall::*;
    use redact_crypto::{
        key::sodiumoxide::{SodiumOxideSymmetricKey, SodiumOxideSymmetricKeyBuilder},
        storage::tests::MockStorer,
        ByteSource, Entry, HasIndex, KeyBuilder, States, SymmetricKey, SymmetricKeyBuilder,
        TypeBuilder, VectorByteSource,
    };
    use serde::Serialize;

    use std::{
        fmt::{self, Debug, Formatter},
        sync::Arc,
    };
    use warp_sessions::{ArcSessionStore, Session, SessionStore};
    use http::StatusCode;
    use crate::render::RenderTemplate;
    use crate::render::TemplateValues::{Secure, Unsecure};

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
    async fn test_submit_data() {
        let token = "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9D";
        let data_path = ".testKey.";

        let mut session = Session::new();
        session.set_cookie_value("testSID".to_owned());
        session.insert("token", token).unwrap();
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
            .return_once(move |_| Ok(Some(token.to_string())));
        let session_store = ArcSessionStore(Arc::new(mock_store));

        let mut render_engine = MockRenderer::new();
        render_engine
            .expect_render()
            .times(1)
            .return_once(move |_| Ok("".to_string()));

        let mut storer = MockStorer::new();
        storer
            .expect_get_indexed::<SymmetricKey>()
            .times(1)
            .withf(|path, index| {
                path == ".keys.default" && *index == Some(SymmetricKey::get_index().unwrap())
            })
            .returning(|_, _| {
                let builder = TypeBuilder::Key(KeyBuilder::Symmetric(
                    SymmetricKeyBuilder::SodiumOxide(SodiumOxideSymmetricKeyBuilder {}),
                ));
                let sosk = SodiumOxideSymmetricKey::new();
                Ok(Entry {
                    path: ".keys.default.".to_owned(),
                    value: States::Unsealed {
                        builder,
                        bytes: ByteSource::Vector(VectorByteSource::new(sosk.key.as_ref())),
                    },
                })
            });
        storer.expect_create().times(1).returning(|_, _| Ok(true));

        let mut token_generator = MockTokenGenerator::new();
        token_generator.expect_generate_token().returning(|| {
            Ok("E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9D".to_owned())
        });

        let relayer = MockRelayer::new();

        let submit_data = post::submit_data(
            session_store,
            Arc::new(render_engine),
            Arc::new(token_generator),
            Arc::new(storer),
            Arc::new(relayer),
        );

        let res = warp::test::request()
            .method("POST")
            .path("/data/E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9D")
            .header("cookie", "sid=testSID")
            .body(format!(
                "path={}&value_type=string&value=qew&submit=Submit",
                 data_path
            ))
            .reply(&submit_data)
            .await;

        assert_eq!(res.status(), 200);
    }

    #[tokio::test]
    async fn test_submit_data_with_relay_and_js_message() {
        let js_message = "ABC";
        let token = "E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9D";
        let data_path = ".testKey.";

        let mut session = Session::new();
        session.set_cookie_value("testSID".to_owned());
        session.insert("token", token).unwrap();
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
            .return_once(move |_| Ok(Some(token.to_string())));
        let session_store = ArcSessionStore(Arc::new(mock_store));

        let mut render_engine = MockRenderer::new();
        render_engine
            .expect_render()
            .times(1)
            .withf(move |template: &RenderTemplate| {
                match &template.value {
                    Secure(secure) => secure.js_message == Some(js_message.to_owned()),
                    Unsecure(_) => false
                }
            })
            .return_once(move |_| Ok("".to_string()));

        let mut storer = MockStorer::new();
        storer
            .expect_get_indexed::<SymmetricKey>()
            .times(1)
            .withf(|path, index| {
                path == ".keys.default" && *index == Some(SymmetricKey::get_index().unwrap())
            })
            .returning(|_, _| {
                let builder = TypeBuilder::Key(KeyBuilder::Symmetric(
                    SymmetricKeyBuilder::SodiumOxide(SodiumOxideSymmetricKeyBuilder {}),
                ));
                let sosk = SodiumOxideSymmetricKey::new();
                Ok(Entry {
                    path: ".keys.default".to_owned(),
                    value: States::Unsealed {
                        builder,
                        bytes: ByteSource::Vector(VectorByteSource::new(sosk.key.as_ref())),
                    },
                })
            });
        storer.expect_create().times(1).returning(|_, _| Ok(true));

        let mut token_generator = MockTokenGenerator::new();
        token_generator.expect_generate_token().returning(|| {
            Ok("E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9D".to_owned())
        });

        let relay_url = "http://asdfs.dsfs/relay";
        let mut relayer = MockRelayer::new();
        relayer.expect_relay()
            .times(1)
            .with(eq(data_path.to_owned()), eq(relay_url.to_owned()))
            .return_once(move |_, _| Ok(StatusCode::OK));

        let submit_data = post::submit_data(
            session_store,
            Arc::new(render_engine),
            Arc::new(token_generator),
            Arc::new(storer),
            Arc::new(relayer),
        );

        let res = warp::test::request()
            .method("POST")
            .path("/data/E0AE2C1C9AA2DB85DFA2FF6B4AAC7A5E51FFDAA3948BECEC353561D513E59A9D")
            .header("cookie", "sid=testSID")
            .body(format!(
                "relay_url={}&path={}&js_message={}&value_type=string&value=qew&submit=Submit",
                relay_url, data_path, js_message
            ))
            .reply(&submit_data)
            .await;

        assert_eq!(res.status(), 200);
    }
}
