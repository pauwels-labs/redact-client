use handlebars::{Handlebars, RenderError as HandlebarsRenderError};
use serde::Serialize;
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use warp::Reply;

#[derive(Error, Debug)]
pub enum RenderError {
    #[error("Failure happened during render")]
    HandlebarsError { source: HandlebarsRenderError },
}

pub struct RenderTemplate<T: Serialize + Send> {
    pub name: &'static str,
    pub value: T,
}

pub struct Rendered<R: Renderer, T: Serialize + Send> {
    render_engine: R,
    render_template: RenderTemplate<T>,
}

impl<R: Renderer, T: Serialize + Send> Rendered<R, T> {
    pub fn new(render_engine: R, render_template: RenderTemplate<T>) -> Rendered<R, T> {
        Rendered {
            render_engine,
            render_template,
        }
    }
}

impl<R: Renderer, T: Serialize + Send> Reply for Rendered<R, T> {
    fn into_response(self) -> warp::reply::Response {
        warp::reply::html(
            self.render_engine
                .render(self.render_template)
                .unwrap_or_else(|err| err.to_string()),
        )
        .into_response()
    }
}

pub trait Renderer: Clone + Send + Sync {
    fn render<T: Serialize + Send>(
        &self,
        template: RenderTemplate<T>,
    ) -> Result<String, RenderError>;
}

#[derive(Debug, Clone)]
pub struct HandlebarsRenderer<'reg> {
    hbs: Arc<Handlebars<'reg>>,
}

impl<'reg> HandlebarsRenderer<'reg> {
    pub fn new(template_mapping: HashMap<&str, &str>) -> HandlebarsRenderer<'reg> {
        let mut hbs = Handlebars::new();
        for (key, val) in template_mapping.iter() {
            hbs.register_template_file(key, val).unwrap();
        }
        HandlebarsRenderer { hbs: Arc::new(hbs) }
    }
}

impl<'reg> Renderer for HandlebarsRenderer<'reg> {
    fn render<T: Serialize + Send>(
        &self,
        template: RenderTemplate<T>,
    ) -> Result<String, RenderError> {
        self.hbs
            .render(template.name, &template.value)
            .map_err(|source| RenderError::HandlebarsError { source })
    }
}
