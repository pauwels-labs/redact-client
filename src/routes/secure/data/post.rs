use std::convert::TryFrom;

use redact_crypto::Data;
use serde::{Deserialize, Serialize};
use warp::Reply;

use crate::{
    render::{
        RenderError, RenderTemplate, Rendered, Renderer, SecureTemplateValues, TemplateValues,
    },
    routes::BadRequestRejection,
};

#[derive(Deserialize, Serialize)]
pub struct QueryParams {
    pub css: Option<String>,
    pub edit: Option<bool>,
    pub data_type: Option<String>,
    pub relay_url: Option<String>,
    pub js_message: Option<String>,
    pub js_height_msg_prefix: Option<String>,
}

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

pub fn reply<R: Renderer>(
    data: Data,
    path: &str,
    token: &str,
    query: QueryParams,
    render_engine: &R,
) -> Result<impl Reply, RenderError> {
    Rendered::new(
        render_engine,
        RenderTemplate {
            name: "secure",
            value: TemplateValues::Secure(SecureTemplateValues {
                data: Some(data),
                path: Some(path.to_owned()),
                token: Some(token.to_owned()),
                css: query.css,
                edit: query.edit,
                data_type: query.data_type,
                relay_url: query.relay_url,
                js_message: query.js_message,
                js_height_msg_prefix: query.js_height_msg_prefix,
                is_binary_data: false,
            }),
        },
    )
}
