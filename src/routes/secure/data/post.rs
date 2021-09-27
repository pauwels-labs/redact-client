use std::convert::TryFrom;

use redact_crypto::Data;
use serde::{Deserialize, Serialize};

use crate::routes::BadRequestRejection;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct BodyParams {
    pub path: String,
    pub value: Option<String>,
    pub value_type: String,
}

impl TryFrom<BodyParams> for Data {
    type Error = BadRequestRejection;

    fn try_from(body: BodyParams) -> Result<Self, Self::Error> {
        if let Some(value) = body.value {
            Ok(match body.value_type.as_ref() {
                "bool" => Data::Bool(value.parse::<bool>().or(Err(BadRequestRejection))?),
                "u64" => Data::U64(value.parse::<u64>().or(Err(BadRequestRejection))?),
                "i64" => Data::I64(value.parse::<i64>().or(Err(BadRequestRejection))?),
                "f64" => Data::F64(value.parse::<f64>().or(Err(BadRequestRejection))?),
                "string" => Data::String(value),
                _ => return Err(BadRequestRejection),
            })
        } else {
            Ok(Data::Bool(false))
        }
    }
}
