mod render;
mod routes;
mod storage;
pub mod token;
mod redis_client;

use render::HandlebarsRenderer;
use rust_config::Configurator;
use serde::Serialize;
use std::collections::HashMap;
use storage::RedactStorer;
use token::FromThreadRng;
use warp::Filter;
use warp_sessions::MemoryStore;
use redis_client::RedisClient;

#[derive(Serialize)]
struct Healthz {}

fn get_port<T: Configurator>(config: &T) -> u16 {
    match config.get_int("server.port") {
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
    }
}

#[tokio::main]
async fn main() {
    // Extract config with a REDACT env var prefix
    let config = rust_config::new("REDACT").unwrap();

    // Determine port to listen on
    let port = get_port(&config);

    // Load HTML templates
    let mut template_mapping = HashMap::new();
    template_mapping.insert("unsecure", "./static/unsecure.handlebars");
    template_mapping.insert("secure", "./static/secure.handlebars");
    let render_engine = HandlebarsRenderer::new(template_mapping).unwrap();

    // Get storage handle
    let storage_url = config.get_str("storage.url").unwrap();
    let data_store = RedactStorer::new(&storage_url);

    // Create an in-memory session store
    let session_store = MemoryStore::new();

    // Connect to redis pool
    let redis_connection_string = config.get_str("redis.conn").unwrap();
    let redis_connection = RedisClient::new(&redis_connection_string);

    // Create a token generator
    let token_generator = FromThreadRng::new();

    // Build out routes
    let health_route = warp::path!("healthz").map(|| warp::reply::json(&Healthz {}));
    let post_routes = warp::post().and(routes::data::post::submit_data(
        session_store.clone(),
        render_engine.clone(),
        token_generator.clone(),
        data_store.clone(),
    ));
    let get_routes = warp::get().and(
        routes::data::get::with_token(
            session_store.clone(),
            render_engine.clone(),
            token_generator.clone(),
            data_store.clone(),
            redis_connection.clone(),
        )
        .or(routes::data::get::without_token(
            session_store.clone(),
            render_engine.clone(),
            token_generator.clone(),
        )
        ),
    );

    // Start the server
    println!("starting server listening on ::{}", port);
    let routes = health_route.or(get_routes).or(post_routes);
    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}
