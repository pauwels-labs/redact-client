mod render;
mod routes;
mod session;
mod storage;
mod token;

use render::HandlebarsRenderer;
use rust_config::Configurator;
use serde::Serialize;
use session::MemoryStore;
use std::collections::HashMap;
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
    let mut template_mapping = HashMap::new();
    template_mapping.insert("unsecure", "./static/unsecure.handlebars");
    template_mapping.insert("secure", "./static/secure.handlebars");
    let render_engine = HandlebarsRenderer::new(template_mapping);

    // Get storage handle
    let storage_url = config.get_str("storage.url").unwrap();
    let data_store = storage::RedactStorer::new(&storage_url);

    // Create an in-memory session store
    let session_store = MemoryStore::new();

    // Build out routes
    let health_route = warp::path!("healthz").map(|| warp::reply::json(&Healthz {}));
    let data_routes = warp::get().and(
        routes::data::get::without_token(session_store.clone(), render_engine.clone()).or(
            routes::data::get::with_token(
                session_store.clone(),
                render_engine.clone(),
                data_store.clone(),
            ),
        ),
    );

    // Start the server
    println!("starting server listening on ::{}", port);
    let routes = health_route.or(data_routes);
    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}
