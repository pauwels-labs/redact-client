use redact_crypto::{CryptoError, StorageError};
use serde_json::Error as JsonSerializationError;
use warp::reject::Reject;

#[derive(Debug)]
pub struct StorageErrorRejection(pub StorageError);
impl Reject for StorageErrorRejection {}

#[derive(Debug)]
pub struct IframeTokensDoNotMatchRejection;
impl Reject for IframeTokensDoNotMatchRejection {}

#[derive(Debug)]
pub struct SessionTokenNotFoundRejection;
impl Reject for SessionTokenNotFoundRejection {}

#[derive(Debug)]
pub struct DataNotFoundRejection;
impl Reject for DataNotFoundRejection {}

#[derive(Debug)]
pub struct BadRequestRejection;
impl Reject for BadRequestRejection {}

#[derive(Debug)]
pub struct SerializationRejection(pub JsonSerializationError);
impl Reject for SerializationRejection {}

#[derive(Debug)]
pub struct CryptoErrorRejection(pub CryptoError);
impl Reject for CryptoErrorRejection {}

#[derive(Debug)]
pub struct RelayRejection;
impl Reject for RelayRejection {}

#[derive(Debug)]
pub struct ProxyRejection(pub reqwest::Error);
impl Reject for ProxyRejection {}
