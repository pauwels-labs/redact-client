mod bootstrap;
mod error;
mod error_handler;
mod render;
mod routes;
pub mod token;

use crate::error_handler::handle_rejection;
use redact_config::Configurator;
use redact_crypto::{RedactStorer, SecretAsymmetricKey, SymmetricKey};
use render::HandlebarsRenderer;
use serde::Serialize;
use std::collections::HashMap;
use token::FromThreadRng;
use warp::Filter;
use warp_sessions::MemoryStore;

#[derive(Serialize)]
struct Healthz {}

fn get_port<T: Configurator>(config: &T) -> u16 {
    match config.get_int("server.port") {
        Ok(port) => {
            if (1..65536).contains(&port) {
                port as u16
            } else {
                println!(
                    "listen port value '{}' is not between 1 and 65535, defaulting to 8080",
                    port
                );
                8080
            }
        }
        Err(e) => {
            match e {
                // Suppress debug logging if server.port was simply not set
                redact_config::ConfigError::NotFound(_) => (),
                _ => println!("{}", e),
            }
            8080
        }
    }
}

#[tokio::main]
async fn main() {
    // Extract config with a REDACT env var prefix
    let config = redact_config::new("REDACT").unwrap();

    // Determine port to listen on
    let port = get_port(&config);

    // Load HTML templates
    let mut template_mapping = HashMap::new();
    template_mapping.insert("unsecure", "./static/unsecure.handlebars");
    template_mapping.insert("secure", "./static/secure.handlebars");
    let render_engine = HandlebarsRenderer::new(template_mapping).unwrap();

    // Get storage handle
    let storage_url = config.get_str("storage.url").unwrap();

    // Get the bootstrap key from config
    let storer = RedactStorer::new(&storage_url);
    let user_akey: SecretAsymmetricKey =
        bootstrap::setup_entry(&config, "crypto.user.key", &storer)
            .await
            .unwrap();
    let client_akey: SecretAsymmetricKey =
        bootstrap::setup_entry(&config, "crypto.client.key", &storer)
            .await
            .unwrap();
    let default_skey: SymmetricKey =
        bootstrap::setup_entry(&config, "crypto.encryption.default", &storer)
            .await
            .unwrap();

    // let default_sym_key_result = storer.get::<SymmetricKey>(".keys.default").await;
    // let default_sym_key = match default_sym_key_result {
    //     Ok(e) => storer.resolve::<SymmetricKey>(e.value).await,
    //     Err(e) => match e {
    //         _ => {
    //             let key = SodiumOxideSymmetricKey::new();
    //             let bytes = ByteSource::Vector(VectorByteSource::new(key.key.as_ref()));
    //             let builder = key.builder().into();

    //             storer
    //                 .create(
    //                     ".keys.default".to_owned(),
    //                     States::Unsealed { builder, bytes },
    //                 )
    //                 .await
    //                 .unwrap();
    //             Ok(SymmetricKey::SodiumOxide(key))
    //         }
    //     },
    // }
    // .unwrap();

    // Create an in-memory session store
    let session_store = MemoryStore::new();

    // Create a token generator
    let token_generator = FromThreadRng::new();

    // Create a CORS filter for the insecure routes that allows any origin
    let unsecure_cors = warp::cors().allow_any_origin().allow_methods(vec!["GET"]);

    // Create a CORS filter for the secure route that allows only localhost origin
    let secure_cors = warp::cors()
        .allow_origin("http://localhost:8080")
        .allow_methods(vec!["GET", "POST"]);

    // Build out routes
    let health_route = warp::path!("healthz").map(|| warp::reply::json(&Healthz {}));
    let post_routes = warp::post()
        .and(routes::data::post::submit_data(
            session_store.clone(),
            render_engine.clone(),
            token_generator.clone(),
            storer.clone(),
        ))
        .with(secure_cors.clone());
    let get_routes = warp::get().and(
        routes::data::get::with_token(
            session_store.clone(),
            render_engine.clone(),
            token_generator.clone(),
            storer.clone(),
        )
        .with(unsecure_cors)
        .or(routes::data::get::without_token(
            session_store.clone(),
            render_engine.clone(),
            token_generator.clone(),
        )
        .with(secure_cors)),
    );

    let routes = health_route
        .or(get_routes)
        .or(post_routes)
        .with(warp::log("routes"))
        .recover(handle_rejection);

    // Start the server
    println!("starting server listening on ::{}", port);
    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}
