mod bootstrap;
mod error;
mod error_handler;
mod relayer;
mod render;
mod routes;
pub mod token;

use crate::error_handler::handle_rejection;
use crate::relayer::MutualTLSRelayer;
use chrono::{prelude::*, Duration};
use pkcs8::PrivateKeyInfo;
use redact_config::Configurator;
use redact_crypto::{
    cert::setup_cert,
    key::sodiumoxide::{
        SodiumOxideEd25519PublicAsymmetricKey, SodiumOxideEd25519SecretAsymmetricKey,
        SodiumOxideSymmetricKey,
    },
    x509::DistinguishedName,
    Entry, HasAlgorithmIdentifier, HasByteSource, HasPublicKey, RedactStorer,
};
use render::HandlebarsRenderer;
use serde::Serialize;
use std::{
    collections::HashMap,
    fs::File,
    io::{ErrorKind, Write},
    sync::Arc,
};
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
    let pkcs12_path = config
        .get_str("storage.tls.client.pkcs12.filepath")
        .unwrap();
    let server_ca_path = config.get_str("storage.tls.server.ca.filepath").unwrap();
    redact_crypto::storage::redact::ClientTlsConfig {
        pkcs12_path,
        server_ca_path,
    }
    .make_current();
    let storer_shared = Arc::new(RedactStorer::new(&storage_url));
    let _: Entry<SodiumOxideSymmetricKey> = bootstrap::setup_entry(
        &config,
        "keys.encryption.symmetric.default",
        &*storer_shared,
    )
    .await
    .unwrap();
    let root_signing_key_entry: Entry<SodiumOxideEd25519SecretAsymmetricKey> =
        bootstrap::setup_entry(&config, "keys.signing.root", &*storer_shared)
            .await
            .unwrap();
    let root_signing_key = root_signing_key_entry.resolve().await.unwrap();
    let tls_key_entry: Entry<SodiumOxideEd25519SecretAsymmetricKey> =
        bootstrap::setup_entry(&config, "keys.signing.tls", &*storer_shared)
            .await
            .unwrap();
    let tls_key = tls_key_entry.resolve().await.unwrap();

    // Make the root signing cert if it doesn't already exist
    let signing_cert_o = config.get_str("certificates.signing.root.o").unwrap();
    let signing_cert_ou = config.get_str("certificates.signing.root.ou").unwrap();
    let signing_cert_cn = config.get_str("certificates.signing.root.cn").unwrap();
    let signing_cert_dn = DistinguishedName {
        o: &signing_cert_o,
        ou: &signing_cert_ou,
        cn: &signing_cert_cn,
    };
    if let Err(e) = File::open(
        config
            .get_str("certificates.signing.root.filepath")
            .unwrap(),
    ) {
        match e.kind() {
            ErrorKind::NotFound => {
                let not_before = Utc::now();
                let not_after = not_before
                    + Duration::days(
                        config
                            .get_int("certificates.signing.root.expires_in")
                            .unwrap(),
                    );
                let root_signing_cert = setup_cert::<_, SodiumOxideEd25519PublicAsymmetricKey>(
                    root_signing_key,
                    None,
                    &signing_cert_dn,
                    None,
                    not_before,
                    not_after,
                    true,
                    None,
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
            }
            _ => Err(e).unwrap(),
        }
    }

    // Make the TLS cert and PKCS12 file if it doesn't exist
    if let Err(e) = File::open(config.get_str("certificates.signing.tls.filepath").unwrap()) {
        match e.kind() {
            ErrorKind::NotFound => {
                let encryption_cert_o = config.get_str("certificates.signing.tls.o").unwrap();
                let encryption_cert_ou = config.get_str("certificates.signing.tls.ou").unwrap();
                let encryption_cert_cn = config.get_str("certificates.signing.tls.cn").unwrap();
                let encryption_cert_dn = DistinguishedName {
                    o: &encryption_cert_o,
                    ou: &encryption_cert_ou,
                    cn: &encryption_cert_cn,
                };
                let not_before = Utc::now();
                let not_after = not_before
                    + Duration::days(
                        config
                            .get_int("certificates.signing.tls.expires_in")
                            .unwrap(),
                    );
                let tls_cert = setup_cert(
                    root_signing_key,
                    Some(&tls_key.public_key().unwrap()),
                    &signing_cert_dn,
                    Some(&encryption_cert_dn),
                    not_before,
                    not_after,
                    false,
                    None,
                )
                .unwrap();
                let mut tls_cert_vec: Vec<u8> = vec![];
                let mut tls_cert_file =
                    File::create(config.get_str("certificates.signing.tls.filepath").unwrap())
                        .unwrap();
                tls_cert_vec
                    .write_all(b"-----BEGIN CERTIFICATE-----\n")
                    .unwrap();
                base64::encode(tls_cert)
                    .as_bytes()
                    .chunks(64)
                    .for_each(|chunk| {
                        tls_cert_vec.write_all(chunk).unwrap();
                        tls_cert_vec.write_all(b"\n").unwrap();
                    });
                tls_cert_vec
                    .write_all(b"-----END CERTIFICATE-----\n")
                    .unwrap();
                tls_cert_file.write_all(&tls_cert_vec).unwrap();

                let tls_key_bs = tls_key.byte_source();
                let mut tls_key_bytes = vec![0x04, 0x20];
                tls_key_bytes.extend_from_slice(&tls_key_bs.get().unwrap()[0..32]);
                let tls_key_pkcs8 =
                    PrivateKeyInfo::new(tls_key.algorithm_identifier(), &tls_key_bytes);
                let mut pkcs12_file =
                    File::create(config.get_str("relayer.certificate.filepath").unwrap()).unwrap();
                pkcs12_file.write_all(&tls_cert_vec).unwrap();
                pkcs12_file
                    .write_all((*tls_key_pkcs8.to_pem()).as_bytes())
                    .unwrap();
            }
            _ => Err(e).unwrap(),
        }
    }

    // Create a relay client which supports mutual TLS
    let relayer =
        MutualTLSRelayer::new(config.get_str("relayer.certificate.filepath").unwrap()).unwrap();

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
        .or(post_routes)
        .or(get_routes)
        .or(proxy_routes)
        .with(warp::log("routes"))
        .recover(handle_rejection);

    // Start the server
    println!("starting server listening on ::{}", port);
    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}
