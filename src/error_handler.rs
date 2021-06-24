use warp::http::StatusCode;
use warp::{reject, Filter, Rejection, Reply};
use std::convert::Infallible;
use std::error::Error;
use crate::routes::{SessionTokenNotFoundRejection, BadRequestRejection, IframeTokensDoNotMatchRejection};
use serde::{Deserialize, Serialize};

/// An API error serializable to JSON.
#[derive(Serialize)]
struct ErrorMessage {
    code: u16,
    message: String,
}

// This function receives a `Rejection` and tries to return a custom
// value, otherwise simply passes the rejection along.
pub async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "NOT FOUND";
    } else if let Some(e) = err.find::<SessionTokenNotFoundRejection>() {
        code = StatusCode::UNAUTHORIZED;
        message = "SESSION TOKEN NOT FOUND";
    } else if let Some(e) = err.find::<IframeTokensDoNotMatchRejection>() {
        code = StatusCode::UNAUTHORIZED;
        message = "IFRAME TOKENS DO NOT MATCH";
    } else if let Some(e) = err.find::<BadRequestRejection>() {
        code = StatusCode::BAD_REQUEST;
        message = "BAD REQUEST";
    } else {
        // We should have expected this... Just log and say its a 500
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "INTERNAL SERVER ERROR";
    }

    let json = warp::reply::json(&ErrorMessage {
        code: code.as_u16(),
        message: message.into(),
    });

    Ok(warp::reply::with_status(json, code))
}