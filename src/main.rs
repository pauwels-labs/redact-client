pub mod render;
mod routes;
pub mod token;

use redact_config::Configurator;
use redact_crypto::{
    keys::sodiumoxide::SodiumOxideSymmetricKey, Buildable, BytesSources, RedactStorer, States,
    Storer, SymmetricKey, VectorBytesSource,
};
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
    //let bootstrap_identity: Key = config.get::<Key>("crypto.bootstrapidentity").unwrap();
    let storer = RedactStorer::new(&storage_url);
    let default_sym_key_result = storer.get::<SymmetricKey>(".keys.default").await;
    let default_sym_key = match default_sym_key_result {
        Ok(e) => storer.resolve::<SymmetricKey>(e.value).await,
        Err(e) => match e {
            _ => {
                let key = SodiumOxideSymmetricKey::new();
                let bytes = BytesSources::Vector(VectorBytesSource::new(key.key.as_ref()));
                let builder = key.builder().into();

                storer
                    .create(
                        ".keys.default".to_owned(),
                        States::Unsealed { builder, bytes },
                    )
                    .await
                    .unwrap();
                Ok(SymmetricKey::SodiumOxide(key))
            }
        },
    }
    .unwrap();

    // Create an in-memory session store
    let session_store = MemoryStore::new();

    // Create a token generator
    let token_generator = FromThreadRng::new();

    // Build out routes
    let health_route = warp::path!("healthz").map(|| warp::reply::json(&Healthz {}));
    let post_routes = warp::post().and(routes::data::post::submit_data(
        session_store.clone(),
        render_engine.clone(),
        token_generator.clone(),
        storer.clone(),
    ));
    let get_routes = warp::get().and(
        routes::data::get::with_token(
            session_store.clone(),
            render_engine.clone(),
            token_generator.clone(),
            storer.clone(),
        )
        .or(routes::data::get::without_token(
            session_store.clone(),
            render_engine.clone(),
            token_generator.clone(),
        )),
    );

    let routes = health_route
        .or(get_routes)
        .or(post_routes)
        .with(warp::log("routes"));

    // Start the server
    println!("starting server listening on ::{}", port);
    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}
