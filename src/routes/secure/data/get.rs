use crate::{
    render::{
        RenderError, RenderTemplate, Rendered, Renderer, SecureTemplateValues, TemplateValues,
    },
    routes::{validate_base64_query_param, Validate},
};
use redact_crypto::Data;
use serde::{Deserialize, Serialize};
use warp::{Rejection, Reply};

#[derive(Deserialize, Serialize)]
pub struct QueryParams {
    pub css: Option<String>,
    pub edit: Option<bool>,
    pub data_type: Option<String>,
    pub relay_url: Option<String>,
    pub js_message: Option<String>,
    pub js_height_msg_prefix: Option<String>,
}

impl Validate for QueryParams {
    fn validate(&self) -> Result<(), Rejection> {
        validate_base64_query_param(self.js_message.clone())?;
        validate_base64_query_param(self.js_height_msg_prefix.clone())?;
        Ok::<_, Rejection>(())
    }
}

pub fn reply<'a, R: Renderer>(
    data: Data,
    path: &str,
    token: &str,
    query: QueryParams,
    render_engine: &'a R,
) -> Result<impl Reply + 'static, RenderError> {
    let is_binary_data = match data {
        Data::Binary(_) => true,
        _ => query.data_type == Some("media".to_owned()),
    };

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
                is_binary_data,
            }),
        },
    )
}
