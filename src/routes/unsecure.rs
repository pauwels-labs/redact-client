pub mod data;

use crate::{render::Renderer, token::TokenGenerator};
use warp::{filters::BoxedFilter, Filter, Rejection, Reply};
use warp_sessions::{
    CookieOptions, SameSiteCookieOption, SessionStore, SessionWithStore, WithSession,
};

pub fn data<T: TokenGenerator, R: Renderer + Clone + Send + Sync + 'static>(
    token_generator: T,
    render_engine: R,
) -> impl Filter<Extract = (impl Reply, String, String), Error = Rejection> + Clone {
    warp::path!("data" / ..).and(data::get(token_generator, render_engine))
}

pub fn session<T, S: SessionStore, R: Reply + 'static>(
    session_store: S,
) -> impl Fn(T) -> BoxedFilter<(WithSession<R>,)>
where
    T: Filter<Extract = (R, String, String), Error = Rejection> + Clone + Send + Sync + 'static,
{
    move |filter: T| {
        warp::any()
            .and(filter)
            .and(warp_sessions::request::with_session(
                session_store.clone(),
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
                |reply: R,
                 path: String,
                 token: String,
                 mut session_with_store: SessionWithStore<S>| async move {
                    session_with_store
                        .session
                        .insert("token", token)
                        .map_err(|_| warp::reject())?;
                    session_with_store.cookie_options.path = Some(path);
                    Ok::<_, Rejection>((reply, session_with_store))
                },
            )
            .untuple_one()
            .and_then(warp_sessions::reply::with_session)
            .boxed()
    }
}

/*
Creates a session that can be used for a raw data request by setting the cookie path to "/raw"
 */
pub fn session_for_processing<T, S: SessionStore, R: Reply + 'static>(
    session_store: S,
) -> impl Fn(T) -> BoxedFilter<(WithSession<R>,)>
    where
        T: Filter<Extract = (R, String), Error = Rejection> + Clone + Send + Sync + 'static,
{
    move |filter: T| {
        warp::any()
            .and(filter)
            .and(warp_sessions::request::with_session(
                session_store.clone(),
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
                |reply: R,
                 token: String,
                 mut session_with_store: SessionWithStore<S>| async move {
                    session_with_store
                        .session
                        .insert("token", token)
                        .map_err(|_| warp::reject())?;
                    session_with_store.cookie_options.path = Some("/raw".to_string());
                    Ok::<_, Rejection>((reply, session_with_store))
                },
            )
            .untuple_one()
            .and_then(warp_sessions::reply::with_session)
            .boxed()
    }
}
