mod crypto;
mod fs_io;
mod render;
mod routes;
mod storage;
pub mod token;

use crypto::{KeypairGenerator, SodiumOxideKeypairGenerator};
use render::HandlebarsRenderer;
use rust_config::Configurator;
use serde::Serialize;
use std::fs::File;
use std::io::prelude::*;
use std::{collections::HashMap, path::PathBuf};
use storage::RedactStorer;
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
                rust_config::ConfigError::NotFound(_) => (),
                _ => println!("{}", e),
            }
            8080
        }
    }
}

#[tokio::main]
async fn main() {
    // Extract config with a REDACT env var prefix
    let config = rust_config::new("REDACT").unwrap();

    // Determine port to listen on
    let port = get_port(&config);

    // Find or generate secret keys
    let public_keys_path = config.get_str("crypto.keys.publicpath").unwrap();
    let secret_keys_path = config.get_str("crypto.keys.privatepath").unwrap();
    let filter = fs_io::FsFilterer::new();
    let public_keys_filtered = filter.dir(&public_keys_path, 1, 1, Some(&"pub")).unwrap();
    for e in public_keys_filtered.io_errors.iter() {
        println!("{}", e)
    }
    let private_keys_filtered = filter.dir(&secret_keys_path, 1, 1, Some(&"key")).unwrap();
    for e in private_keys_filtered.io_errors.iter() {
        println!("{}", e)
    }

    let mut default_key_name = match config.get_str("crypto.keys.defaultkeyname") {
        Ok(dkn) => {
            if dkn.is_empty() {
                "admin".to_owned()
            } else {
                dkn
            }
        }
        Err(e) => {
            println!(
                "error getting crypto.keys.defaultkeyname, defaulting to 'admin': {}",
                e
            );
            "admin".to_owned()
        }
    };

    let (pk, sk) = match public_keys_filtered
        .paths
        .iter()
        .find(|&path| path.file_stem().unwrap().to_str().unwrap() == default_key_name)
    {
        Some(path) => {
            let mut pk_file = File::open(path).unwrap();
            let mut sk_file = File::open(
                PathBuf::from(&secret_keys_path)
                    .join(path.file_stem().unwrap().to_str().unwrap().to_owned() + ".key"),
            )
            .unwrap();
            let mut pk_arr: [u8; 32] = [0; 32];
            let mut sk_arr: [u8; 32] = [0; 32];
            assert!(pk_file.read(&mut pk_arr).unwrap() == 32);
            assert!(sk_file.read(&mut sk_arr).unwrap() == 32);
            (pk_arr, sk_arr)
        }
        None => {
            SodiumOxideKeypairGenerator::init().unwrap();
            let keys = SodiumOxideKeypairGenerator::create();
            let pk = keys.0;
            let sk = keys.1;
            let new_pk_path = PathBuf::from(&public_keys_path)
                .join(PathBuf::from(format!("{}.pub", default_key_name)));
            let new_sk_path = PathBuf::from(&secret_keys_path)
                .join(PathBuf::from(format!("{}.key", default_key_name)));
            let mut pk_file = File::create(new_pk_path).unwrap();
            pk_file.write_all(&pk).unwrap();
            let mut sk_file = File::create(new_sk_path).unwrap();
            sk_file.write_all(&sk).unwrap();
            (pk, sk)
        }
    };

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
        )
        .or(routes::data::get::without_token(
            session_store.clone(),
            render_engine.clone(),
            token_generator.clone(),
        )),
    );

    // Start the server
    println!("starting server listening on ::{}", port);
    let routes = health_route.or(get_routes).or(post_routes);
    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}
