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

#[cfg(test)]
mod tests {
    use crate::routes::proxy;
    use crate::relayer::{tests::MockRelayer, RelayError::RelayRequestError};
    use mockall::predicate::*;
    use std::sync::Arc;
    use warp::http::HeaderValue;

    #[tokio::test]
    async fn test_post() {
        let host_url = "http://host.com/proxy/session/whatever";

        let expected_response = http::response::Builder::new()
            .header("Content-Type", "text/html")
            .status(200)
            .body("brr".to_owned())
            .unwrap();

        let mut relayer = MockRelayer::new();
        relayer.expect_get()
            .times(1)
            .with(eq(host_url.to_owned()))
            .return_once(move |_| Ok(reqwest::Response::from(expected_response)));

        let proxy = proxy::post(
            Arc::new(relayer),
        );

        let res = warp::test::request()
            .method("POST")
            .path("/proxy")
            .body(format!("{{\"host_url\":\"{}\"}}", host_url))
            .header("Content-Type", "application/json")
            .reply(&proxy)
            .await;

        assert_eq!(res.status(), 200);
        assert_eq!(res.body(), "brr");
        assert_eq!(
            res.headers().get("Content-Type"),
            Some(&HeaderValue::from_static("text/html"))
        );
    }

    #[tokio::test]
    async fn test_post_relay_request_error() {
        let host_url = "http://host.com/proxy/session/whatever";

        let mut relayer = MockRelayer::new();
        relayer.expect_get()
            .times(1)
            .with(eq(host_url.to_owned()))
            .return_once(move |_| Err(RelayRequestError{source: None}));

        let proxy = proxy::post(
            Arc::new(relayer),
        );

        let res = warp::test::request()
            .method("POST")
            .path("/proxy")
            .body(format!("{{\"host_url\":\"{}\"}}", host_url))
            .header("Content-Type", "application/json")
            .reply(&proxy)
            .await;

        assert_eq!(res.status(), 500);
    }
}
