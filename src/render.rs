use handlebars::{
    Context, Handlebars, Helper, Output, RenderContext, RenderError as HandlebarsRenderError,
    TemplateFileError,
};
use redact_data::{Data, DataValue};
use serde::Serialize;
use std::ops::Deref;
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use warp::{reject::Reject, Reply};

#[derive(Error, Debug)]
pub enum RenderError {
    #[error("Failure happened during render")]
    RenderError { source: HandlebarsRenderError },
    #[error("Failed to load template file")]
    TemplateFileError { source: TemplateFileError },
}

impl Reject for RenderError {}

#[derive(Serialize, Debug, Default)]
pub struct UnsecureTemplateValues {
    pub path: String,
    pub token: String,
    pub css: Option<String>,
    pub edit: Option<bool>,
    pub index: Option<i64>,
    pub fetch_id: Option<String>,
}

#[derive(Serialize, Debug, Default)]
pub struct SecureTemplateValues {
    pub data: Option<Data>,
    pub path: Option<String>,
    pub token: Option<String>,
    pub css: Option<String>,
    pub edit: Option<bool>,
}

impl std::convert::From<TemplateFileError> for RenderError {
    fn from(source: TemplateFileError) -> Self {
        RenderError::TemplateFileError { source }
    }
}

pub struct RenderTemplate<T: Serialize + Send> {
    pub name: &'static str,
    pub value: T,
}

pub struct Rendered {
    reply: warp::reply::Html<String>,
}

impl Rendered {
    pub fn new<E: Renderer, T: Serialize + Send>(
        render_engine: E,
        render_template: RenderTemplate<T>,
    ) -> Result<Rendered, RenderError> {
        let reply = warp::reply::html(render_engine.render(render_template)?);

        Ok(Rendered { reply })
    }
}

impl Reply for Rendered {
    fn into_response(self) -> warp::reply::Response {
        self.reply.into_response()
    }
}

fn data_as_input(
    h: &Helper,
    _: &Handlebars,
    _: &Context,
    _: &mut RenderContext,
    out: &mut dyn Output,
) -> Result<(), HandlebarsRenderError> {
    // get parameter from helper or throw an error
    let value = h
        .param(0)
        .and_then(|v| {
            Some(DataValue::from(
                v.value().get("value")?.as_str()?.to_owned(),
            ))
        })
        .ok_or_else(|| {
            HandlebarsRenderError::new("Value provided as a DataValue in the data_as_input helper must be interpretable as a string-type")
        })?;
    match value {
        DataValue::Bool(ref b) => {
            if *b {
                out
		.write("<input type=\"checkbox\" class=\"checkbox\" name=\"value\" value=\"true\" checked>")
            } else {
                out.write(
                    "<input type=\"checkbox\" class=\"checkbox\" name=\"value\" value=\"true\">",
                )
            }
        }
        DataValue::U64(n) => out.write(&format!(
            "<input type=\"number\" class=\"number\" name=\"value\" min=\"0\" value=\"{}\">",
            n
        )),
        DataValue::I64(n) => out.write(&format!(
            "<input type=\"number\" class=\"number\" name=\"value\" value=\"{}\">",
            n
        )),
        DataValue::F64(n) => out.write(&format!(
            "<input type=\"number\" class=\"number\" name=\"value\" step=\"any\" value=\"{}\">",
            n
        )),
        DataValue::String(s) => out.write(&format!(
            "<input type=\"text\" class=\"text\" name=\"value\" value=\"{}\">",
            s
        )),
    }?;
    Ok(())
}

pub trait Renderer: Clone + Send + Sync {
    fn render<T: Serialize + Send>(
        &self,
        template: RenderTemplate<T>,
    ) -> Result<String, RenderError>;
}

impl<U> Renderer for Arc<U>
where
    U: Renderer,
{
    fn render<T: Serialize + Send>(
        &self,
        template: RenderTemplate<T>,
    ) -> Result<String, RenderError> {
        self.deref().render(template)
    }
}

#[derive(Debug, Clone)]
pub struct HandlebarsRenderer<'reg> {
    hbs: Arc<Handlebars<'reg>>,
}

impl<'reg> HandlebarsRenderer<'reg> {
    pub fn new(
        template_mapping: HashMap<&str, &str>,
    ) -> Result<HandlebarsRenderer<'reg>, RenderError> {
        let mut hbs = Handlebars::new();
        for (key, val) in template_mapping.iter() {
            hbs.register_template_file(key, val)?;
        }
        hbs.register_helper("data_as_input", Box::new(data_as_input));
        Ok(HandlebarsRenderer { hbs: Arc::new(hbs) })
    }
}

impl<'reg> Renderer for HandlebarsRenderer<'reg> {
    fn render<T: Serialize + Send>(
        &self,
        template: RenderTemplate<T>,
    ) -> Result<String, RenderError> {
        self.hbs
            .render(template.name, &template.value)
            .map_err(|source| RenderError::RenderError { source })
    }
}

#[cfg(test)]
pub mod tests {
    use super::{RenderError, RenderTemplate, Renderer};
    use mockall::predicate::*;
    use mockall::*;
    use serde::Serialize;
    use std::collections::HashMap;

    mock! {
    pub Renderer {
            pub fn render(&self, template: RenderTemplate<HashMap<String, String>>) -> Result<String, RenderError>;
    }
    impl Clone for Renderer {
            fn clone(&self) -> Self;
    }
    }

    impl Renderer for MockRenderer {
        fn render<T: Serialize + Send>(
            &self,
            template: RenderTemplate<T>,
        ) -> Result<String, RenderError> {
            let value_str = serde_json::to_string(&template.value).unwrap();
            let value_hm: HashMap<String, String> = serde_json::from_str(&value_str).unwrap();

            let typed_template = RenderTemplate {
                name: template.name,
                value: value_hm,
            };
            self.render(typed_template)
        }
    }
}
