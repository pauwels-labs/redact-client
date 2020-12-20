pub use async_session::{MemoryStore, Session, SessionStore};
use std::convert::Infallible;
use thiserror::Error;
use warp::{
    reject::{self, Reject},
    Filter, Rejection,
};

#[derive(Error, Debug)]
pub enum SessionError {
    #[error("Failed to load session")]
    LoadError { source: async_session::Error },
    #[error("Failed to store session")]
    StoreError { source: async_session::Error },
}

impl Reject for SessionError {}

pub fn with_session<T: SessionStore>(
    sess_store: T,
) -> impl Filter<Extract = (Session,), Error = Rejection> + Clone {
    warp::any()
        .and(sessions(sess_store))
        .and(warp::cookie::optional("sid"))
        .and_then(|sess_store: T, sid_cookie| async move {
            match sid_cookie {
                Some(sid) => match sess_store.load_session(sid).await {
                    Ok(Some(sess)) => {
                        println!("session found",);
                        Ok(sess)
                    }
                    Ok(None) => {
                        println!("sid cookie found, but no matching session, creating new");
                        Ok(Session::new())
                    }
                    Err(source) => Err(reject::custom(SessionError::LoadError { source })),
                },
                None => {
                    println!("no sid cookie found, creating new");
                    Ok(Session::new())
                }
            }
        })
}

fn sessions<T: SessionStore>(store: T) -> impl Filter<Extract = (T,), Error = Infallible> + Clone {
    warp::any().map(move || store.clone())
}
