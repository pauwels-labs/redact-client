pub mod data;
pub mod error;
pub(crate) mod proxy;

pub use data::get::{with_token, without_token};
pub use data::post::submit_data;
pub use error::{
    BadRequestRejection, CryptoErrorRejection, DataNotFoundRejection,
    IframeTokensDoNotMatchRejection, SerializationRejection, SessionTokenNotFoundRejection,
    StorageErrorRejection,
};
