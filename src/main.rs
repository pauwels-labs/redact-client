mod bootstrap;
mod error;
mod error_handler;
mod relayer;
mod render;
mod routes;
pub mod token;

use crate::relayer::MutualTLSRelayer;
use crate::{bootstrap::DistinguishedName, error_handler::handle_rejection};
use chrono::{prelude::*, Duration};
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
    let relayer =
        MutualTLSRelayer::new(config.get_str("relayer.certificate.filepath").unwrap()).unwrap();

    // Get storage handle
    let storage_url = config.get_str("storage.url").unwrap();

    // Get the bootstrap key from config
    let storer_shared = Arc::new(RedactStorer::new(&storage_url));
    let root_signing_key_entry: Entry<SodiumOxideEd25519SecretAsymmetricKey> =
        bootstrap::setup_entry(&config, "keys.signing.root", &*storer_shared)
            .await
            .unwrap();
    let root_signing_key = root_signing_key_entry.resolve().await.unwrap();
    let tls_key_entry: Entry<SodiumOxideCurve25519SecretAsymmetricKey> =
        bootstrap::setup_entry(&config, "keys.encryption.asymmetric.tls", &*storer_shared)
            .await
            .unwrap();
    let tls_key = tls_key_entry.take_resolve().await.unwrap();

    let signing_cert_o = config.get_str("certificates.signing.root.o").unwrap();
    let signing_cert_ou = config.get_str("certificates.signing.root.ou").unwrap();
    let signing_cert_cn = config.get_str("certificates.signing.root.cn").unwrap();
    let signing_cert_dn = DistinguishedName {
        o: &signing_cert_o,
        ou: &signing_cert_ou,
        cn: &signing_cert_cn,
    };
    let not_before = Utc::now();
    let not_after = not_before
        + Duration::days(
            config
                .get_int("certificates.signing.root.expires_in")
                .unwrap(),
        );
    let root_signing_cert = bootstrap::setup_cert::<_, SodiumOxideEd25519PublicAsymmetricKey>(
        root_signing_key,
        None,
        &signing_cert_dn,
        None,
        not_before,
        not_after,
        true,
    )
    .unwrap();
    let mut root_signing_cert_file = File::create(
        config
            .get_str("certificates.signing.root.filepath")
            .unwrap(),
    )
    .unwrap();
    root_signing_cert_file
        .write_all(b"-----BEGIN CERTIFICATE-----\n")
        .unwrap();
    base64::encode(root_signing_cert)
        .as_bytes()
        .chunks(64)
        .for_each(|chunk| {
            root_signing_cert_file.write_all(chunk).unwrap();
            root_signing_cert_file.write_all(b"\n").unwrap();
        });
    root_signing_cert_file
        .write_all(b"-----END CERTIFICATE-----\n")
        .unwrap();

    let encryption_cert_o = config.get_str("certificates.encryption.tls.o").unwrap();
    let encryption_cert_ou = config.get_str("certificates.encryption.tls.ou").unwrap();
    let encryption_cert_cn = config.get_str("certificates.encryption.tls.cn").unwrap();
    let encryption_cert_dn = DistinguishedName {
        o: &encryption_cert_o,
        ou: &encryption_cert_ou,
        cn: &encryption_cert_cn,
    };
    let not_before = Utc::now();
    let not_after = not_before
        + Duration::days(
            config
                .get_int("certificates.encryption.tls.expires_in")
                .unwrap(),
        );
    let tls_cert = bootstrap::setup_cert(
        root_signing_key,
        Some(&tls_key.public_key().unwrap()),
        &signing_cert_dn,
        Some(&encryption_cert_dn),
        not_before,
        not_after,
        false,
    )
    .unwrap();
    let mut tls_cert_file = File::create(
        config
            .get_str("certificates.encryption.tls.filepath")
            .unwrap(),
    )
    .unwrap();
    tls_cert_file
        .write_all(b"-----BEGIN CERTIFICATE-----\n")
        .unwrap();
    base64::encode(tls_cert)
        .as_bytes()
        .chunks(64)
        .for_each(|chunk| {
            tls_cert_file.write_all(chunk).unwrap();
            tls_cert_file.write_all(b"\n").unwrap();
        });
    tls_cert_file
        .write_all(b"-----END CERTIFICATE-----\n")
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
