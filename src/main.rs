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
    Entry, HasAlgorithmIdentifier, HasByteSource, HasPublicKey, RedactStorer, Storer,
};
use reqwest::Certificate;
use serde::Serialize;
use std::{
    fs::File,
    io::{ErrorKind, Write},
    path::Path,
    sync::Arc,
};
use token::FromThreadRng;
use warp::Filter;
use warp_sessions::MemoryStore;
use warp::http::header::{HeaderMap, HeaderValue};
use crate::routes::secure::data::{get_raw, get_processing};

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

    // Fetch HTML template renderer and load pre-defined templates into it
    let render_engine = Arc::new(bootstrap::setup_html_render_engine().unwrap());

    // Create the internally-used Redact storer; this is the self-storer
    let storer_shared = Arc::new(RedactStorer::new(&config.get_str("storage.url").unwrap()));

    // Fetch or create the root signing key from which all other identities will be derived
    let root_signing_key_entry: Entry<SodiumOxideEd25519SecretAsymmetricKey> =
        bootstrap::setup_entry(&config, "keys.signing.root")
            .await
            .unwrap();
    let root_signing_key = root_signing_key_entry.resolve().await.unwrap();

    // Fetch or create the key that will be used for initiating client TLS connections
    let tls_key_entry: Entry<SodiumOxideEd25519SecretAsymmetricKey> =
        bootstrap::setup_entry(&config, "keys.signing.tls")
            .await
            .unwrap();
    let tls_key = tls_key_entry.resolve().await.unwrap();

    // Create the certificate for the signing key if it doesn't already exist
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
                let path_str = &config
                    .get_str("certificates.signing.root.filepath")
                    .unwrap();

                let path = Path::new(path_str);
                let path_parent = path.parent();
                if let Some(path) = path_parent {
                    std::fs::create_dir_all(path).unwrap();
                }
                let mut root_signing_cert_file = File::create(path).unwrap();
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
    let tls_cert_path_str = config.get_str("certificates.signing.tls.filepath").unwrap();
    if let Err(e) = File::open(&tls_cert_path_str) {
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
                let path_str = &config.get_str("certificates.signing.tls.filepath").unwrap();

                let path = Path::new(path_str);
                let path_parent = path.parent();
                if let Some(path) = path_parent {
                    std::fs::create_dir_all(path).unwrap();
                }
                let mut tls_cert_file = File::create(path).unwrap();
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
            }
            _ => Err(e).unwrap(),
        }
    }

    let pkcs12_path_str = &config
        .get_str("relayer.tls.client.pkcs12.filepath")
        .unwrap();
    if let Err(e) = File::open(pkcs12_path_str) {
        match e.kind() {
            ErrorKind::NotFound => {
                let tls_key_bs = tls_key.byte_source();
                let mut tls_key_bytes = vec![0x04, 0x20];
                tls_key_bytes.extend_from_slice(&tls_key_bs.get().unwrap()[0..32]);
                let tls_key_pkcs8 =
                    PrivateKeyInfo::new(tls_key.algorithm_identifier(), &tls_key_bytes);
                let pkcs12_path = Path::new(pkcs12_path_str);
                let pkcs12_path_parent = pkcs12_path.parent();
                if let Some(path) = pkcs12_path_parent {
                    std::fs::create_dir_all(path).unwrap();
                }
                let tls_cert_bytes = std::fs::read(&tls_cert_path_str).unwrap();
                let mut pkcs12_file = File::create(pkcs12_path).unwrap();
                pkcs12_file.write_all(&tls_cert_bytes).unwrap();
                pkcs12_file
                    .write_all((*(tls_key_pkcs8.to_pem(pkcs8::LineEnding::LF)).unwrap()).as_bytes())
                    .unwrap();
            }
            _ => Err(e).unwrap(),
        }
    };

    // Setup mTLS configuration for all calls to a Redact storer
    let pkcs12_path = config
        .get_str("storage.tls.client.pkcs12.filepath")
        .unwrap();
    let server_ca_path = config
        .get_str("storage.tls.server.ca.filepath")
        .ok()
        .and_then(|path| if path.is_empty() { None } else { Some(path) });
    redact_crypto::storage::redact::ClientTlsConfig {
        pkcs12_path,
        server_ca_path,
    }
    .make_current();

    // Create the default encryption key if it doesn't exist
    let default_encryption_key_entry: Entry<SodiumOxideSymmetricKey> =
        bootstrap::setup_entry(&config, "keys.encryption.symmetric.default")
            .await
            .unwrap();
    storer_shared
        .create(default_encryption_key_entry)
        .await
        .unwrap();

    // Create a relay client which supports mutual TLS
    let relayer_root = config
        .get_str("relayer.tls.server.ca.filepath")
        .ok()
        .and_then(|path| match std::fs::read(path) {
            Ok(b) => Some(vec![Certificate::from_pem(b.as_slice()).unwrap()]),
            Err(e) => match e.kind() {
                ErrorKind::NotFound => None,
                _ => Err(e).unwrap(),
            },
        });
    let relayer = MutualTLSRelayer::new(
        config
            .get_str("relayer.tls.client.pkcs12.filepath")
            .unwrap(),
        relayer_root.as_deref(),
    )
    .unwrap();

    // Create an in-memory session store for managing secure client sessions
    let session_store = MemoryStore::new();

    // Create a token generator for generating the iframe tokens
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

    // Simple health-check route
    let health_route = warp::path!("healthz")
        .and(warp::get())
        .map(|| warp::reply::json(&Healthz {}))
        .with(unsecure_cors.clone());

    // Routes called with no CSRF token, hosts iframes to routes with CSRF protection
    let unsecure_routes = routes::unsecure(token_generator.clone(), render_engine.clone())
        .with(warp::wrap_fn(routes::unsecure::session(
            session_store.clone(),
        )))
        .with(unsecure_cors.clone());

    // Routes called with a CSRF token, only to be called by the client itself
    let secure_routes = routes::secure(
        storer_shared.clone(),
        render_engine.clone(),
        token_generator.clone(),
        relayer.clone(),
    )
    .with(warp::wrap_fn(routes::secure::session(
        session_store.clone(),
    )))
    .with(secure_cors.clone());

    let raw_data_route = get_raw(
        storer_shared.clone(),
    )
    .with(warp::wrap_fn(routes::secure::session_without_invalidation(
        session_store.clone(),
    )))
    .with(secure_cors.clone());

    let processing_route = get_processing(
        render_engine.clone(),
        token_generator.clone())
    .with(warp::wrap_fn(routes::unsecure::session_for_processing(
        session_store.clone(),
    )))
    .with(unsecure_cors.clone());

    // Routes for an external website to trigger requests from the client to itself
    let proxy_routes = routes::proxy(relayer).with(unsecure_cors_post.clone());

    // Assemble all routes into one handler
    let routes = health_route
        .or(unsecure_routes)
        .or(secure_routes)
        .or(proxy_routes)
        .or(raw_data_route)
        .or(processing_route)
        .with(warp::log("routes"))
        .recover(handle_rejection);

    // Start the server
    println!("starting server listening on ::{}", port);
    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}
