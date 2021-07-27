use handlebars::{
    Context, Handlebars, Helper, Output, RenderContext, RenderError as HandlebarsRenderError,
    TemplateError as HandlebarsTemplateError,
};
use redact_crypto::Data;
use serde::Serialize;
use std::convert::From;
use std::ops::Deref;
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use warp::{reject::Reject, Reply};

#[derive(Error, Debug)]
pub enum RenderError {
    #[error("Failure happened during render")]
    RenderError { source: HandlebarsRenderError },
    #[error("Failed to load template file")]
    TemplateError { source: HandlebarsTemplateError },
}

impl Reject for RenderError {}

#[derive(Serialize, Debug, PartialEq)]
pub enum TemplateValues {
    Unsecure(UnsecureTemplateValues),
    Secure(SecureTemplateValues),
}

#[derive(Serialize, Debug, Default, PartialEq)]
pub struct UnsecureTemplateValues {
    pub path: String,
    pub token: String,
    pub css: Option<String>,
    pub edit: Option<bool>,
    pub data_type: Option<String>,
    pub relay_url: Option<String>,
    pub js_message: Option<String>,
}

#[derive(Serialize, Debug, Default, PartialEq)]
pub struct SecureTemplateValues {
    pub data: Option<Data>,
    pub path: Option<String>,
    pub token: Option<String>,
    pub css: Option<String>,
    pub edit: Option<bool>,
    pub relay_url: Option<String>,
    pub js_message: Option<String>,
}

impl From<HandlebarsTemplateError> for RenderError {
    fn from(source: HandlebarsTemplateError) -> Self {
        RenderError::TemplateError { source }
    }
}

pub struct RenderTemplate {
    pub name: &'static str,
    pub value: TemplateValues,
}

pub struct Rendered {
    reply: warp::reply::Html<String>,
}

impl Rendered {
    pub fn new<E: Renderer>(
        render_engine: E,
        render_template: RenderTemplate,
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

fn data_display(
    h: &Helper,
    _: &Handlebars,
    _: &Context,
    _: &mut RenderContext,
    out: &mut dyn Output,
) -> Result<(), HandlebarsRenderError> {
    // get parameter from helper or throw an error
    let value: Data = h
        .param(0)
        .ok_or_else(|| HandlebarsRenderError::new("Value provided as data_display cannot be null"))
        .and_then(|data| {
            serde_json::value::from_value(data.value().to_owned()).map_err(|e| e.into())
        })?;

    out.write(&value.to_string()).map_err(|e| e.into())
}

fn data_input(
    h: &Helper,
    _: &Handlebars,
    _: &Context,
    _: &mut RenderContext,
    out: &mut dyn Output,
) -> Result<(), HandlebarsRenderError> {
    // get parameter from helper or throw an error
    let data: Data = h
        .param(0)
        .ok_or_else(|| HandlebarsRenderError::new("Value provided to data_input cannot be null"))
        .and_then(|data| {
            serde_json::value::from_value(data.value().to_owned()).map_err(|e| e.into())
        })?;
    match data {
        Data::Bool(b) => {
            out.write("<input type=\"hidden\" name=\"value_type\" value=\"bool\">")?;
            if b {
                out
    		.write("<input type=\"checkbox\" class=\"checkbox\" name=\"value\" value=\"true\" checked autofocus>")
            } else {
                out.write(
                    "<input type=\"checkbox\" class=\"checkbox\" name=\"value\" value=\"true\" autofocus>",
                )
            }
        }
        Data::U64(n) => {
            out.write("<input type=\"hidden\" name=\"value_type\" value=\"u64\">")?;
            out.write(&format!(
                "<input type=\"number\" class=\"number\" name=\"value\" min=\"0\" value=\"{}\" autofocus>",
                n
            ))
        }
        Data::I64(n) => {
            out.write("<input type=\"hidden\" name=\"value_type\" value=\"i64\">")?;
            out.write(&format!(
                "<input type=\"number\" class=\"number\" name=\"value\" value=\"{}\" autofocus>",
                n
            ))
        }
        Data::F64(n) => {
            out.write("<input type=\"hidden\" name=\"value_type\" value=\"f64\">")?;
            out.write(&format!(
                "<input type=\"number\" class=\"number\" name=\"value\" step=\"any\" value=\"{}\" autofocus>",
                n
            ))
        }
        Data::String(s) => {
            out.write("<input type=\"hidden\" name=\"value_type\" value=\"string\">")?;
            out.write(&format!(
                "<input type=\"text\" class=\"text\" name=\"value\" value=\"{}\" autofocus>",
                s
            ))
        }
    }
    .map_err(|e| e.into())
}

pub trait Renderer: Clone + Send + Sync {
    fn render(&self, template: RenderTemplate) -> Result<String, RenderError>;
}

impl<U> Renderer for Arc<U>
where
    U: Renderer,
{
    fn render(&self, template: RenderTemplate) -> Result<String, RenderError> {
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
        hbs.register_helper("data_input", Box::new(data_input));
        hbs.register_helper("data_display", Box::new(data_display));
        Ok(HandlebarsRenderer { hbs: Arc::new(hbs) })
    }
}

impl<'reg> Renderer for HandlebarsRenderer<'reg> {
    fn render(&self, template: RenderTemplate) -> Result<String, RenderError> {
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

    mock! {
    pub Renderer {
            pub fn render(&self, template: RenderTemplate) -> Result<String, RenderError>;
    }
    impl Clone for Renderer {
            fn clone(&self) -> Self;
    }
    }

    impl Renderer for MockRenderer {
        fn render(&self, template: RenderTemplate) -> Result<String, RenderError> {
            self.render(RenderTemplate {
                name: template.name,
                value: template.value,
            })
        }
    }
}
