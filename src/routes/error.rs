use redact_crypto::StorageError as KeyStorageError;
use redact_data::StorageError as DataStorageError;
use serde_json::Error as JsonSerializationError;
use warp::reject::Reject;

#[derive(Debug)]
pub struct KeyStorageErrorRejection(pub KeyStorageError);
impl Reject for KeyStorageErrorRejection {}

#[derive(Debug)]
pub struct DataStorageErrorRejection(pub DataStorageError);
impl Reject for DataStorageErrorRejection {}

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
