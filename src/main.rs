mod bootstrap;
mod error;
mod error_handler;
mod relayer;
mod render;
mod routes;
pub mod token;

use crate::error_handler::handle_rejection;
use crate::relayer::MutualTLSRelayer;
use chrono::prelude::*;
use redact_config::Configurator;
use redact_crypto::{
    key::sodiumoxide::{
        SodiumOxideCurve25519SecretAsymmetricKey, SodiumOxideEd25519PublicAsymmetricKey,
        SodiumOxideEd25519SecretAsymmetricKey,
    },
    Entry, HasPublicKey, RedactStorer,
};
use render::HandlebarsRenderer;
use serde::Serialize;
use std::sync::Arc;
use std::{collections::HashMap, fs::File, io::Write, sync::Arc};
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

    // Create a relay client which supports mutual TLS
    let relayer = MutualTLSRelayer::new(config.get_str("certificate.filepath").unwrap()).unwrap();

    // Get storage handle
    let storage_url = config.get_str("storage.url").unwrap();

    // Get the bootstrap key from config
    let storer_shared = Arc::new(RedactStorer::new(&storage_url));
    let user_signing_root_key_entry: Entry<SodiumOxideEd25519SecretAsymmetricKey> =
        bootstrap::setup_entry(&config, "keys.user.signing.root", &storer)
            .await
            .unwrap();
    let user_signing_root_key = user_signing_root_key_entry.resolve().await.unwrap();
    let user_encryption_root_key_entry: Entry<SodiumOxideCurve25519SecretAsymmetricKey> =
        bootstrap::setup_entry(&config, "keys.user.encryption.asymmetric.default", &storer)
            .await
            .unwrap();
    let user_encryption_root_key = user_encryption_root_key_entry.take_resolve().await.unwrap();

    let root_signing_cert = bootstrap::setup_cert::<_, SodiumOxideEd25519PublicAsymmetricKey>(
        user_signing_root_key,
        None,
        "pauwels",
        None,
        Utc::now(),
        Utc.ymd(2031, 1, 1).and_hms(0, 0, 0),
        true,
    )
    .unwrap();
    let mut signing_cert_file = File::create("certs/signing-cert.raw").unwrap();
    signing_cert_file
        .write_all(root_signing_cert.as_slice())
        .unwrap();

    let root_encryption_cert = bootstrap::setup_cert(
        user_signing_root_key,
        Some(&user_encryption_root_key.public_key().unwrap()),
        "pauwels",
        Some("pauwels-encryption"),
        Utc::now(),
        Utc.ymd(2031, 1, 1).and_hms(0, 0, 0),
        false,
    )
    .unwrap();
    let mut encryption_cert_file = File::create("certs/encryption-cert.raw").unwrap();
    encryption_cert_file
        .write_all(root_encryption_cert.as_slice())
        .unwrap();

    // Create an in-memory session store
    let session_store = MemoryStore::new();

    // Create a token generator
    let token_generator = FromThreadRng::new();

    // Create a CORS filter for the insecure routes that allows any origin
    let unsecure_cors = warp::cors().allow_any_origin().allow_methods(vec!["GET"]);
    let unsecure_cors_post = warp::cors()
        .allow_any_origin()
        .allow_methods(vec!["GET", "POST", "OPTIONS"])
        .allow_headers(vec!["content-type"]);

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
            storer_shared.clone(),
            relayer.clone(),
        ))
        .with(secure_cors.clone());
    let get_routes = warp::get().and(
        routes::data::get::with_token(
            session_store.clone(),
            render_engine.clone(),
            token_generator.clone(),
            storer_shared.clone(),
        )
        .with(unsecure_cors.clone())
        .or(routes::data::get::without_token(
            session_store.clone(),
            render_engine.clone(),
            token_generator.clone(),
        )
        .with(secure_cors)),
    );

    let proxy_routes = warp::any()
        .and(warp::post().and(routes::proxy::post(relayer)))
        .with(unsecure_cors_post.clone());

    let routes = health_route
        .or(get_routes)
        .or(post_routes)
        .or(proxy_routes)
        .with(warp::log("routes"))
        .recover(handle_rejection);

    // Start the server
    println!("starting server listening on ::{}", port);
    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}
