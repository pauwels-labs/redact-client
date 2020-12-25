pub use async_session::{MemoryStore, Session, SessionStore};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter, Result as FmtResult};
use thiserror::Error;
use warp::{
    reject::{self, Reject},
    Rejection, Reply,
};

#[derive(Error, Debug)]
pub enum SessionError {
    #[error("Failed to load session")]
    LoadError { source: async_session::Error },
    #[error("Failed to store session")]
    StoreError { source: async_session::Error },
}

impl Reject for SessionError {}

impl std::convert::From<SessionError> for Rejection {
    fn from(error: SessionError) -> Self {
        reject::custom(error)
    }
}

pub struct SessionWithStore<S: SessionStore> {
    pub session: Session,
    pub session_store: S,
    pub cookie_options: CookieOptions,
}

pub mod request {
    use super::{CookieOptions, Session, SessionError, SessionStore, SessionWithStore};
    use warp::{reject, Filter, Rejection};

    pub fn with_session<T: SessionStore>(
        session_store: T,
        cookie_options: Option<CookieOptions>,
    ) -> impl Filter<Extract = (SessionWithStore<T>,), Error = Rejection> + Clone {
        let cookie_options = match cookie_options {
            Some(co) => co,
            None => CookieOptions::default(),
        };
        warp::any()
            .and(warp::any().map(move || session_store.clone()))
            .and(warp::cookie::optional("sid"))
            .and(warp::any().map(move || cookie_options.clone()))
            .and_then(
		|session_store: T,
		sid_cookie: Option<String>,
		cookie_options: CookieOptions| async move {
                    match sid_cookie {
			Some(sid) => match session_store.load_session(sid).await {
                            Ok(Some(session)) => {
				Ok::<_, Rejection>(SessionWithStore {
                                    session,
                                    session_store,
				    cookie_options,
				})
                            }
                            Ok(None) => {
				Ok::<_, Rejection>(SessionWithStore {
                                    session: Session::new(),
                                    session_store,
				    cookie_options,
				})
                            }
                            Err(source) => Err(Rejection::from(SessionError::LoadError { source })),
			},
			None => {
                            Ok::<_, Rejection>(SessionWithStore {
				session: Session::new(),
				session_store,
				cookie_options,
                            })
			}
                    }
		},
            )
    }
}

pub mod reply {
    use super::{SessionStore, SessionWithStore, WithSession};
    use warp::Reply;

    pub async fn with_session<T: Reply, S: SessionStore>(
        reply: T,
        session_with_store: SessionWithStore<S>,
    ) -> Result<WithSession<T, S>, std::convert::Infallible> {
        WithSession::new(reply, session_with_store).await
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub enum SameSiteCookieOption {
    None,
    Lax,
    Strict,
}

impl Default for SameSiteCookieOption {
    fn default() -> Self {
        SameSiteCookieOption::Lax
    }
}

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct CookieOptions {
    pub cookie_name: String,
    pub cookie_value: Option<String>,
    pub max_age: Option<u64>,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<SameSiteCookieOption>,
}

impl Display for CookieOptions {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let cookie_value = match &self.cookie_value {
            Some(cv) => cv,
            None => "",
        };
        let mut header_str = format!("{}={}", self.cookie_name, cookie_value);
        if let Some(max_age) = &self.max_age {
            header_str += &format!("; Max-Age={}", max_age);
        }
        if let Some(domain) = &self.domain {
            header_str += &format!("; Domain={}", domain);
        }
        if let Some(path) = &self.path {
            header_str += &format!("; Path={}", path);
        }
        if self.secure {
            header_str += "; Secure";
        }
        if self.http_only {
            header_str += "; HttpOnly";
        }
        if let Some(same_site) = &self.same_site {
            header_str = match same_site {
                SameSiteCookieOption::None => header_str + "; SameSite=None",
                SameSiteCookieOption::Lax => header_str + "; SameSite=Lax",
                SameSiteCookieOption::Strict => header_str + "; SameSite=Strict",
            }
        }

        write!(f, "{}", header_str)
    }
}

pub struct WithSession<T: Reply, S: SessionStore> {
    reply: T,
    session_with_store: SessionWithStore<S>,
}

impl<T, S> WithSession<T, S>
where
    T: Reply,
    S: SessionStore,
{
    pub async fn new(
        reply: T,
        session_with_store: SessionWithStore<S>,
    ) -> Result<WithSession<T, S>, std::convert::Infallible> {
        let mut ws = WithSession {
            reply,
            session_with_store,
        };

        let session_clone = ws.session_with_store.session.clone();
        if ws.session_with_store.session.is_destroyed() {
            ws.session_with_store
                .session_store
                .destroy_session(ws.session_with_store.session)
                .await
                .unwrap();
        } else {
            if ws.session_with_store.session.data_changed() {
                if let Some(sid) = ws
                    .session_with_store
                    .session_store
                    .store_session(ws.session_with_store.session)
                    .await
                    .unwrap()
                {
                    ws.session_with_store.cookie_options.cookie_value = Some(sid);
                }
            }
        }

        ws.session_with_store.session = session_clone;
        Ok(ws)
    }
}

impl<T, S> warp::Reply for WithSession<T, S>
where
    T: Reply,
    S: SessionStore,
{
    fn into_response(self) -> warp::reply::Response {
        let mut cookie_options = self.session_with_store.cookie_options;
        if self.session_with_store.session.is_destroyed() {
            cookie_options.cookie_value = Some("".to_string());
            cookie_options.max_age = Some(0);
        }

        if let Some(_) = cookie_options.cookie_value {
            warp::reply::with_header(self.reply, "Set-Cookie", cookie_options.to_string())
                .into_response()
        } else {
            self.reply.into_response()
        }
    }
}
