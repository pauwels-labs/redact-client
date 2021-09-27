use warp::{Filter, Rejection, Reply};

use crate::{render::Renderer, routes::validated_query_params, token::TokenGenerator};

pub mod get;
pub mod post;

pub fn get<T: TokenGenerator, R: Renderer>(
    token_generator: T,
    render_engine: R,
) -> impl Filter<Extract = (impl Reply, String, String), Error = Rejection> + Clone {
    warp::get()
        .and(warp::path!(String))
        .and(warp::any().map(move || token_generator.clone().generate_token().unwrap()))
        .and(validated_query_params::<get::QueryParams>())
        .and(warp::any().map(move || render_engine.clone()))
        .and_then(
            |path: String, token: String, query: get::QueryParams, render_engine: R| async move {
                let secure_path = format!("/secure/data/{}/{}", &path, &token);
                Ok::<_, Rejection>((
                    get::reply(&secure_path, query, render_engine)?,
                    secure_path,
                    token,
                ))
            },
        )
        .untuple_one()
}
