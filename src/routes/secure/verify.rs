use warp::{path::Peek, Filter, Rejection};
use warp_sessions::{CookieOptions, SameSiteCookieOption, SessionStore, SessionWithStore};

use crate::routes::{
    error::NoPathTokenProvided, IframeTokensDoNotMatchRejection, SessionTokenNotFoundRejection,
};

pub fn verify<S: SessionStore>(
    session_store: S,
) -> impl Filter<Extract = ((),), Error = Rejection> + Clone {
    warp::any()
        .and(warp::path::peek().map(|peek: Peek| {
            if let Some(token) = peek.segments().last() {
                Some(token.to_owned())
            } else {
                None
            }
        }))
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
        .and_then(
            move |token: Option<String>, session_with_store: SessionWithStore<S>| async move {
                let token = match token {
                    Some(t) => t,
                    None => return Err(warp::reject::custom(NoPathTokenProvided)),
                };
                if let Some(session_token) = session_with_store.session.get::<String>("token") {
                    if session_token != token {
                        Err(warp::reject::custom(IframeTokensDoNotMatchRejection))
                    } else {
                        Ok(())
                    }
                } else {
                    Err(warp::reject::custom(SessionTokenNotFoundRejection))
                }
            },
        )
}
