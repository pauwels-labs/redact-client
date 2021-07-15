use warp::{Filter, Rejection, Reply, http::Response};
use crate::relayer::Relayer;
use crate::routes::error::{RelayRejection, ProxyRejection};
use serde::{Deserialize, Serialize};
use reqwest;
use warp::http::HeaderValue;

#[derive(Deserialize, Serialize, Debug, Clone)]
struct ProxyBodyParams {
    host_url: String
}

pub fn post<Q: Relayer>(
    relayer: Q
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::any()
        .and(warp::path!("proxy"))
        .and(warp::filters::body::json::<ProxyBodyParams>())
        .and(warp::any().map(move || relayer.clone()))
        .and_then(
            move |
                body_params: ProxyBodyParams,
                relayer: Q
            | async move {
                relayer.get(body_params.host_url)
                    .await
                    .map_err(|_| warp::reject::custom(RelayRejection))
            }
        )
        .and_then(
            move |response: reqwest::Response| async move {
                Ok::<_, Rejection>(Response::builder()
                    .status(response.status())
                    .header("Content-Type", response.headers()
                        .get("Content-Type")
                        .unwrap_or(&HeaderValue::from_static("")))
                    .body(
                        response.text()
                            .await
                            .map_err(ProxyRejection)?
                    ))
            }
        )
}
