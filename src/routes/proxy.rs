use crate::error::ClientError;
use crate::relayer::Relayer;
use crate::routes::error::{ProxyRejection, RelayRejection};
use addr::parser::DomainName;
use addr::psl::List;
use reqwest;
use serde::{Deserialize, Serialize};
use url::Url;
use warp::http::HeaderValue;
use warp::{http::Response, Filter, Rejection, Reply};

#[derive(Deserialize, Serialize, Debug, Clone)]
struct ProxyBodyParams {
    host_url: String,
}

pub fn post<Q: Relayer>(
    relayer: Q,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::any()
        .and(warp::path!("proxy"))
        .and(warp::filters::body::json::<ProxyBodyParams>())
        .and(warp::header::<String>("Origin"))
        .and(warp::any().map(move || relayer.clone()))
        .and_then(
            move |body_params: ProxyBodyParams, origin_header: String, relayer: Q| async move {
                let origin_root = parse_url_root(&origin_header)
                    .map_err(|_| warp::reject::custom(RelayRejection))?;
                let dest_root = parse_url_root(&body_params.host_url)
                    .map_err(|_| warp::reject::custom(RelayRejection))?;

                if dest_root != origin_root {
                    Err(warp::reject::custom(RelayRejection))
                } else {
                    relayer
                        .get(body_params.host_url)
                        .await
                        .map_err(|_| warp::reject::custom(RelayRejection))
                }
            },
        )
        .and_then(move |response: reqwest::Response| async move {
            Ok::<_, Rejection>(
                Response::builder()
                    .status(response.status())
                    .header(
                        "Content-Type",
                        response
                            .headers()
                            .get("Content-Type")
                            .unwrap_or(&HeaderValue::from_static("")),
                    )
                    .body(response.text().await.map_err(ProxyRejection)?),
            )
        })
}

fn parse_url_root(url: &str) -> Result<Option<String>, ClientError> {
    let origin_domain = Url::parse(url)
        .map_err(|e| ClientError::InternalError {
            source: Box::new(e),
        })
        .map(|p| p.domain().map(str::to_string))?;

    match origin_domain {
        Some(origin) => {
            let parsed_result =
                List.parse_domain_name(&origin)
                    .map_err(|e| ClientError::DomainParsingError {
                        kind: e.kind(),
                        input: e.input().to_owned(),
                    })?;
            Ok(parsed_result.root().map(str::to_string))
        }
        None => Ok(Some("".to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use crate::relayer::{tests::MockRelayer, RelayError::RelayRequestError};
    use crate::routes::proxy;
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
        relayer
            .expect_get()
            .times(1)
            .with(eq(host_url.to_owned()))
            .return_once(move |_| Ok(reqwest::Response::from(expected_response)));

        let proxy = proxy::post(Arc::new(relayer));

        let res = warp::test::request()
            .method("POST")
            .path("/proxy")
            .body(format!("{{\"host_url\":\"{}\"}}", host_url))
            .header("Content-Type", "application/json")
            .header("Origin", "http://host.com")
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
        let host_url = "http://abr.host.co.uk/proxy/session/whatever";

        let mut relayer = MockRelayer::new();
        relayer
            .expect_get()
            .times(1)
            .with(eq(host_url.to_owned()))
            .return_once(move |_| Err(RelayRequestError { source: None }));

        let proxy = proxy::post(Arc::new(relayer));

        let res = warp::test::request()
            .method("POST")
            .path("/proxy")
            .body(format!("{{\"host_url\":\"{}\"}}", host_url))
            .header("Content-Type", "application/json")
            .header("Origin", "http://host.co.uk")
            .reply(&proxy)
            .await;

        assert_eq!(res.status(), 500);
    }

    #[tokio::test]
    async fn test_post_relay_request_different_origin() {
        let host_url = "http://host.com/proxy/session/whatever";

        let mut relayer = MockRelayer::new();
        relayer.expect_get().times(0);

        let proxy = proxy::post(Arc::new(relayer));

        let res = warp::test::request()
            .method("POST")
            .path("/proxy")
            .body(format!("{{\"host_url\":\"{}\"}}", host_url))
            .header("Content-Type", "application/json")
            .header("Origin", "http://abc.com")
            .reply(&proxy)
            .await;

        assert_eq!(res.status(), 500);
    }

    #[tokio::test]
    async fn test_parse_url_root() {
        let host_url = "http://www.abc.123.host.co.uk";
        let res = proxy::parse_url_root(host_url).unwrap();
        assert_eq!(res, Some("host.co.uk".to_owned()));
    }

    #[tokio::test]
    async fn test_parse_url_root_bad_domain() {
        let host_url = "https://127.0.0.1/";
        let res = proxy::parse_url_root(host_url).unwrap();
        assert_eq!(res, Some("".to_owned()));
    }

    #[tokio::test]
    async fn test_parse_url_root_invalid_domain() {
        let host_url = "scoopdolladolla./.a";
        let res = proxy::parse_url_root(host_url);
        assert!(res.is_err());
    }
}
