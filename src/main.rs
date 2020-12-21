mod session;
mod storage;
mod token;

use handlebars::Handlebars;
use rust_config::Configurator;
use serde::Serialize;
use session::MemoryStore;
use std::sync::Arc;
use warp::Filter;

#[derive(Serialize)]
struct Healthz {}

#[tokio::main]
async fn main() {
    // Extract config with a REDACT env var prefix
    let config = rust_config::new("REDACT").unwrap();

    // Determine port to listen on
    let port = match config.get_int("server.port") {
        Ok(port) => {
            if port < 1 || port > 65535 {
                println!(
                    "listen port value '{}' is not between 1 and 65535, defaulting to 8080",
                    port
                );
                8080 as u16
            } else {
                port as u16
            }
        }
        Err(e) => {
            match e {
                // Suppress debug logging if server.port was simply not set
                rust_config::ConfigError::NotFound(_) => (),
                _ => println!("{}", e),
            }
            8080 as u16
        }
    };

    // Load HTML templates
    let mut hb = Handlebars::new();
    hb.register_template_file("unsecure", "./static/unsecure.handlebars")
        .unwrap();
    hb.register_template_file("secure", "./static/secure.handlebars")
        .unwrap();
    let hb = Arc::new(hb);

    // Get storage url
    let storage_url = config.get_str("storage.url").unwrap();

    // Create an in-memory session store
    let store = MemoryStore::new();

    // Build out routes
    let health_route = warp::path!("healthz").map(|| warp::reply::json(&Healthz {}));
    let data_routes = filters::data(storage_url, store, hb.clone());

    // Start the server
    println!("starting server");
    let routes = health_route.or(data_routes);
    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}

mod filters {
    use crate::session::{self, Session, SessionStore};
    use crate::storage;
    use crate::token;
    use handlebars::Handlebars;
    use serde::{Deserialize, Serialize};
    use serde_json::Value::{Bool, Null, Number, String as SerdeString};
    use std::{collections::BTreeMap, sync::Arc};
    use warp::{Filter, Rejection, Reply};

    fn render<T>(template: WithTemplate<T>, hbs: Arc<Handlebars>) -> impl warp::Reply
    where
        T: Serialize,
    {
        let render = hbs
            .render(template.name, &template.value)
            .unwrap_or_else(|err| err.to_string());
        warp::reply::html(render)
    }

    struct WithTemplate<T: Serialize> {
        name: &'static str,
        value: T,
    }

    #[derive(Deserialize, Serialize)]
    struct WithCss {
        css: Option<String>,
    }

    pub fn data<T: SessionStore>(
        url: String,
        sess_store: T,
        hb: Arc<Handlebars>,
    ) -> impl Filter<Extract = impl Reply + '_, Error = Rejection> + Clone {
        secure_data_get(url.clone(), sess_store.clone(), hb.clone())
            .or(unsecure_data_get(sess_store.clone(), hb.clone()))
    }

    pub fn secure_data_get<T: SessionStore>(
        storage_url: String,
        sess_store: T,
        hb: Arc<Handlebars>,
    ) -> impl Filter<Extract = impl Reply + '_, Error = Rejection> + Clone {
        // Create a reusable closure to render template
        let handlebars = move |(with_template, path, token): (_, String, String)| {
            let hb = hb.clone();

            async move {
                Ok::<_, Rejection>(warp::reply::with_header(
                    render(with_template, hb),
                    "Set-Cookie",
                    format!(
                        "sid=; Max-Age=0; SameSite=Strict; Path=/data/{}/{}; HttpOnly",
                        path, token
                    ),
                ))
            }
        };

        warp::path!("data" / String / String)
            .and(warp::get())
            .and(warp::query::<WithCss>())
            .and(warp::any().map(move || storage_url.clone()))
            .and(session::with_session(sess_store.clone()))
            .and_then(
                move |path: String,
                      query_token: String,
                      css: WithCss,
                      url: String,
                      sess: Session| {
                    let sess_store = sess_store.clone();
                    let mut template_values = BTreeMap::new();

                    match css.css {
                        Some(css_str) => template_values.insert("css".to_string(), css_str),
                        _ => None,
                    };

                    async move {
                        println!("secure data route");
                        println!("path: {}, query_token: {}", path, query_token);
                        match sess.get("token") {
                            Some::<String>(sess_token) => {
                                sess_store.destroy_session(sess).await.map_err(|source| {
                                    println!("error storing session: {:?}", source);
                                    warp::reject::custom(session::SessionError::StoreError {
                                        source,
                                    })
                                })?;

                                if sess_token != query_token {
                                    template_values.insert(
                                        "data".to_string(),
                                        "TOKENS DID NOT MATCH".to_string(),
                                    );
                                    Ok((
                                        WithTemplate {
                                            name: "secure",
                                            value: template_values,
                                        },
                                        path,
                                        query_token,
                                    ))
                                } else {
                                    storage::get(&url, path.clone()).await.map(|data| {
                                        println!("{:?}", data);
                                        let val = match data.value {
                                            Null => "".to_string(),
                                            Bool(b) => b.to_string(),
                                            Number(n) => n.to_string(),
                                            SerdeString(s) => s.to_string(),
                                            _ => "".to_string(),
                                        };
                                        template_values.insert("data".to_string(), val);
                                        Ok::<_, Rejection>((
                                            WithTemplate {
                                                name: "secure",
                                                value: template_values,
                                            },
                                            path,
                                            query_token,
                                        ))
                                    })?
                                }
                            }
                            None => {
                                sess_store.destroy_session(sess).await.map_err(|source| {
                                    println!("error storing session: {:?}", source);
                                    warp::reject::custom(session::SessionError::StoreError {
                                        source,
                                    })
                                })?;

                                template_values
                                    .insert("data".to_string(), "COULD NOT GET TOKEN".to_string());
                                Ok((
                                    WithTemplate {
                                        name: "secure",
                                        value: template_values,
                                    },
                                    path,
                                    query_token,
                                ))
                            }
                        }
                    }
                },
            )
            .and_then(handlebars)
    }

    pub fn unsecure_data_get<T: SessionStore>(
        sess_store: T,
        hb: Arc<Handlebars>,
    ) -> impl Filter<Extract = impl Reply + '_, Error = Rejection> + Clone {
        // Create a reusable closure to render template
        let handlebars =
            move |(with_template, sess_id, path, token): (_, String, String, String)| {
                let hb = hb.clone();
                async move {
                    Ok::<_, Rejection>(warp::reply::with_header(
                        render(with_template, hb),
                        "Set-Cookie",
                        format!(
                            "sid={}; Max-Age=60; SameSite=Strict; Path=/data/{}/{}; HttpOnly",
                            sess_id, path, token
                        ),
                    ))
                }
            };

        warp::path!("data" / String)
            .and(warp::get())
            .and(warp::query::<WithCss>())
            .and(session::with_session(sess_store.clone()))
            .and_then(move |path: String, css: WithCss, mut sess: Session| {
                println!("unsecure data route");
                let sess_store = sess_store.clone();
                async move {
                    let token = token::generate_token()?;
                    println!("generated token: {}", token.clone());
                    sess.insert("token", token.clone())
                        .map_err(|_| warp::reject())?;
                    let mut template_values = BTreeMap::new();
                    template_values.insert("path".to_string(), path.clone());
                    template_values.insert("token".to_string(), token.clone());

                    match css.css {
                        Some(css_str) => template_values.insert("css".to_string(), css_str),
                        _ => None,
                    };

                    sess.regenerate();
                    let sid = sess_store
                        .store_session(sess)
                        .await
                        .map_err(|source| {
                            println!("here: {:?}", source);
                            warp::reject::custom(session::SessionError::StoreError { source })
                        })?
                        .unwrap();
                    println!("template_values: {:?}", template_values);
                    Ok::<_, Rejection>((
                        WithTemplate {
                            name: "unsecure",
                            value: template_values,
                        },
                        sid,
                        path,
                        token,
                    ))
                }
            })
            .and_then(handlebars)
    }
}
