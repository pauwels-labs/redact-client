use handlebars::{
    Context, Handlebars, Helper, Output, RenderContext, RenderError as HandlebarsRenderError,
    TemplateError as HandlebarsTemplateError,
};
use itertools::free::join;
use redact_crypto::{BinaryType, Data};
use serde::Serialize;
use std::ops::Deref;
use std::{collections::HashMap, sync::Arc};
use std::{convert::From, path::Path};
use strum::IntoEnumIterator;
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
    Processing(ProcessingTemplateValues),
}

#[derive(Serialize, Debug, Default, PartialEq)]
pub struct UnsecureTemplateValues {
    pub path: String,
    pub css: Option<String>,
    pub edit: Option<bool>,
    pub data_type: Option<String>,
    pub relay_url: Option<String>,
    pub js_message: Option<String>,
    pub js_height_msg_prefix: Option<String>,
}

#[derive(Serialize, Debug, Default, PartialEq)]
pub struct SecureTemplateValues {
    pub data: Option<Data>,
    pub path: Option<String>,
    pub token: Option<String>,
    pub css: Option<String>,
    pub edit: Option<bool>,
    pub data_type: Option<String>,
    pub relay_url: Option<String>,
    pub js_message: Option<String>,
    pub js_height_msg_prefix: Option<String>,
    pub is_binary_data: bool,
}

#[derive(Serialize, Debug, Default, PartialEq)]
pub struct ProcessingTemplateValues {
    pub token: Option<String>,
    pub css: Option<String>,
    pub script: Option<String>,
    pub html: Option<String>
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
        render_engine: &E,
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

    match value {
        Data::Binary(b) => {
            match b {
                Some(binary) => {
                    match binary.binary_type {
                        BinaryType::VideoMP4 | BinaryType::VideoMPEG => {
                            out.write(
                                &format!(
                                    "<video controls id=\"data-video\"><source src=\"data:{};base64, {}\"></video>",
                                    binary.binary_type.to_string(),
                                    binary.binary
                                )
                            ).map_err(|e| e.into())
                        },
                        _ => out.write(
                            &format!(
                                "<img id=\"data\" src=\"data:{};base64, {}\"/>",
                                binary.binary_type.to_string(),
                                binary.binary
                            )
                        ).map_err(|e| e.into()),
                    }
                }
                None => out.write("").map_err(|e| e.into()),
            }

        },
        b => out.write(&format!("<p id=\"data\">{}</p>", &b.to_string())).map_err(|e| e.into())
    }
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
        Data::Binary(_) => {
            out.write("<input type=\"hidden\" name=\"value_type\" value=\"media\">")?;
            out.write(&format!(
                "<input type=\"file\" class=\"file\" name=\"value\" accept=\"{}\"autofocus>",
                &join(BinaryType::iter(), ",")
            ))
        }
    }
    .map_err(|e| e.into())
}

pub trait Renderer {
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

#[derive(Debug)]
pub struct HandlebarsRenderer<'reg> {
    hbs: Handlebars<'reg>,
}

impl<'reg> HandlebarsRenderer<'reg> {
    pub fn new<P: AsRef<Path>>(
        template_mapping: HashMap<&str, P>,
    ) -> Result<HandlebarsRenderer<'reg>, RenderError> {
        let mut hbs = Handlebars::new();
        for (key, val) in template_mapping.iter() {
            hbs.register_template_file(key, val)?;
        }
        hbs.register_helper("data_input", Box::new(data_input));
        hbs.register_helper("data_display", Box::new(data_display));
        Ok(HandlebarsRenderer { hbs })
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
