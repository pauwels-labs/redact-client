use handlebars::{Handlebars, RenderError as HandlebarsRenderError, TemplateFileError};
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
