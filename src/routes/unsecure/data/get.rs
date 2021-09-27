use crate::{
    render::{
        RenderError, RenderTemplate, Rendered, Renderer, TemplateValues, UnsecureTemplateValues,
    },
    routes::{validate_base64_query_param, Validate},
};
use serde::{Deserialize, Serialize};
use warp::{Rejection, Reply};

#[derive(Deserialize, Serialize)]
pub struct QueryParams {
    css: Option<String>,
    edit: Option<bool>,
    data_type: Option<String>,
    relay_url: Option<String>,
    js_message: Option<String>,
    js_height_msg_prefix: Option<String>,
}

impl Validate for QueryParams {
    fn validate(&self) -> Result<(), Rejection> {
        validate_base64_query_param(self.js_message.clone())?;
        validate_base64_query_param(self.js_height_msg_prefix.clone())?;
        Ok::<_, Rejection>(())
    }
}

pub fn reply<R: Renderer>(
    path: &str,
    query: QueryParams,
    render_engine: R,
) -> Result<impl Reply, RenderError> {
    Rendered::new(
        render_engine,
        RenderTemplate {
            name: "unsecure",
            value: TemplateValues::Unsecure(UnsecureTemplateValues {
                path: path.to_owned(),
                css: query.css,
                edit: query.edit,
                data_type: query.data_type,
                relay_url: query.relay_url,
                js_height_msg_prefix: query.js_height_msg_prefix,
                js_message: query.js_message,
            }),
        },
    )
}
