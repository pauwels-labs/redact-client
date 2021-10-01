pub mod data;

use crate::{
    relayer::Relayer,
    render::Renderer,
    routes::error::{
        IframeTokensDoNotMatchRejection, NoPathTokenProvided, SessionTokenNotFoundRejection,
    },
    token::TokenGenerator,
};
use redact_crypto::Storer;
use std::sync::Arc;
use warp::{filters::BoxedFilter, path::Peek, Filter, Rejection, Reply};
use warp_sessions::{
    CookieOptions, SameSiteCookieOption, Session, SessionStore, SessionWithStore, WithSession,
};

pub fn data<H: Storer, R: Renderer + Clone + Send + 'static, T: TokenGenerator, Q: Relayer>(
    storer: Arc<H>,
    render_engine: R,
    token_generator: T,
    relayer: Q,
) -> impl Filter<Extract = (Box<dyn Reply>, String, Option<String>, Option<String>), Error = Rejection>
       + Clone {
    warp::path!("data" / ..).and(
        data::get(
            storer.clone(),
            render_engine.clone(),
            token_generator.clone(),
        )
        .or(data::post(render_engine, token_generator, storer, relayer))
        .unify(),
    )
}

pub fn session<T, S: SessionStore>(
    session_store: S,
) -> impl Fn(T) -> BoxedFilter<(WithSession<Box<dyn Reply>>,)>
where
    T: Filter<
            Extract = (Box<dyn Reply>, String, Option<String>, Option<String>),
            Error = Rejection,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    move |filter: T| {
        warp::any()
            .and(warp::path::peek().map(|peek: Peek| {
                if let Some(token) = peek.segments().last() {
                    Some(token.to_owned())
                } else {
                    None
                }
            }))
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
                move |token: Option<String>, session_with_store: SessionWithStore<S>| async move {
                    let token = match token {
                        Some(t) => t,
                        None => return Err(warp::reject::custom(NoPathTokenProvided)),
                    };
                    if let Some(session_token) = session_with_store.session.get::<String>("token") {
                        if session_token != token {
                            Err(warp::reject::custom(IframeTokensDoNotMatchRejection))
                        } else {
                            Ok(session_with_store)
                        }
                    } else {
                        Err(warp::reject::custom(SessionTokenNotFoundRejection))
                    }
                },
            )
            .and(filter)
            .and_then(
                |mut session_with_store: SessionWithStore<S>,
                 reply: Box<dyn Reply>,
                 old_path: String,
                 new_path: Option<String>,
                 token: Option<String>| async move {
                    session_with_store.cookie_options.path = Some(old_path);
                    session_with_store.session.destroy();

                    match (new_path, token) {
                        (Some(new_path), Some(token)) => {
                            let mut new_session = SessionWithStore::<S> {
                                session: Session::new(),
                                session_store: session_with_store.session_store.clone(),
                                cookie_options: CookieOptions {
                                    cookie_name: "sid",
                                    cookie_value: None,
                                    max_age: Some(60),
                                    domain: None,
                                    path: Some(new_path),
                                    secure: false,
                                    http_only: true,
                                    same_site: Some(SameSiteCookieOption::None),
                                },
                            };

                            new_session
                                .session
                                .insert("token", token)
                                .map_err(|_| warp::reject())?;
                            Ok::<_, Rejection>((
                                Box::new(
                                    warp_sessions::reply::with_session(reply, session_with_store)
                                        .await?,
                                ) as Box<dyn Reply>,
                                new_session,
                            ))
                        }
                        _ => Ok::<_, Rejection>((
                            Box::new(reply) as Box<dyn Reply>,
                            session_with_store,
                        )),
                    }
                },
            )
            .untuple_one()
            .and_then(warp_sessions::reply::with_session)
            .boxed()
    }
}
