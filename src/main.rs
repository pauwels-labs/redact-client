use std::sync::{Arc, Mutex};
use warp::Filter;

pub mod config;
pub mod error;
pub mod key;
pub mod session;
use crate::config::Configurator;
use key::Key;
use session::SessionManager;

#[tokio::main]
async fn main() {
    let config = config::new().unwrap();
    let key_path = config.get_str("key.path").unwrap();
    let key: Arc<Key> = Arc::new(Key::new(&key_path).unwrap());

    let healthz = warp::path!("healthz").map(|| "ok");
    let apiv1 = warp::path("api").and(warp::path("v1"));

    let sess_mgr = Arc::new(Mutex::new(SessionManager::new()));

    let data = warp::path("data");
    let unsecure_data = data
        .and(warp::path::full())
        .and(session::get_session(sess_mgr.clone()))
        .and_then(move |path, sess| handlers::unsecure_data(path, sess));

    let decrypt_key = key.clone();
    let secure_data = warp::path("secure")
        .and(data)
        .and(session::get_session(sess_mgr.clone()))
        .and(warp::path::full())
        .and(warp::query::<models::SecureOptions>())
        .and_then(move |sess, path, opts| {
            handlers::secure_data(sess, path, opts, decrypt_key.clone())
        });

    warp::serve(warp::get().and(healthz.or(apiv1.and(unsecure_data.or(secure_data)))))
        .run(([127, 0, 0, 1], 8080))
        .await;
}

mod handlers {
    use super::error::Error;
    use super::models::SecureOptions;
    use super::session::Session;
    use super::Key;
    use std::fmt::{Display, Formatter};
    use std::sync::{Arc, Mutex};
    use warp::http::{Response, StatusCode};
    use warp::path::FullPath;
    use warp::{Rejection, Reply};

    #[derive(Debug)]
    pub struct HttpError {
        pub status_code: StatusCode,
        pub err: Error,
    }

    impl Display for HttpError {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}: {}", self.status_code, self.err.to_string())
        }
    }

    impl HttpError {
        fn new(status_code: u16, msg: String, mut fields: Vec<String>) -> HttpError {
            let status_code = StatusCode::from_u16(status_code)
                .unwrap_or(StatusCode::from_u16(500).ok().unwrap());

            fields.push("status_code".to_owned());
            fields.push(status_code.to_string());
            HttpError {
                status_code,
                err: Error::new(msg, fields),
            }
        }
    }

    pub async fn unsecure_data(
        path: FullPath,
        sess: Arc<Mutex<Session>>,
    ) -> Result<impl Reply, Rejection> {
        let path_str = path.as_str().to_owned();
        let all_path_parts = path_str.trim_matches('/').split('/');
        let path_parts = all_path_parts.skip(3).collect::<Vec<&str>>().join("");
        let secure_token = super::session::gen_token().unwrap();
        let mut sess = sess.lock().unwrap();
        sess.insert(&path_parts, &secure_token);

        let body = r#"<!DOCTYPE html>
<html>
  <head></head>
  <body>
    <div id="iframe-container"></div>
    <script>
      window.onload = init;

      function init() {
        var iframe = document.createElement("iframe");
        iframe.setAttribute("src", "http://localhost:8080/api/v1/secure/data/"#
            .to_owned()
            + &path_parts
            + "?token="
            + &secure_token
            + r#"");
        iframe.setAttribute("sandbox", "");
        iframe.style.width = "500px";
        iframe.style.height = "500px";
        document.getElementById("iframe-container").appendChild(iframe);
      }
    </script>
  </body>
</html>
"#;

        Response::builder()
            .status(StatusCode::OK)
            .header(
                "Set-Cookie",
                "sid=".to_owned() + &sess.id + "; Path=/api/v1",
            )
            .body(body)
            .map_err(|e| warp::reject::custom(Error::new(format!("{}", e), vec![])))
    }

    pub async fn secure_data(
        sess: Arc<Mutex<Session>>,
        path: FullPath,
        opts: SecureOptions,
        key: Arc<Key>,
    ) -> Result<impl Reply, Rejection> {
        let resp = Response::builder().status(StatusCode::OK);
        let query_token = match opts.token {
            Some(t) => t,
            None => {
                let body = r#"<!DOCTYPE html>
<html>
  <head></head>
  <body>
    <p>invalid</p>
  </body>
</html>
"#;

                return resp
                    .body(body.to_owned())
                    .map_err(|e| warp::reject::custom(Error::new(format!("{}", e), vec![])));
            }
        };

        let path_str = path.as_str().to_owned();
        let all_path_parts = path_str.trim_matches('/').split('/');
        let path_parts = all_path_parts.skip(4).collect::<Vec<&str>>().join("");
        let mut sess = sess.lock().unwrap();
        let sess_token = match sess.consume(&path_parts, &query_token) {
            Some(t) => t,
            None => {
                let body = r#"<!DOCTYPE html>
<html>
  <head></head>
  <body>
    <p>invalid</p>
  </body>
</html>
"#;

                return resp
                    .body(body.to_owned())
                    .map_err(|e| warp::reject::custom(Error::new(format!("{}", e), vec![])));
            }
        };
        if query_token != sess_token {
            println!("sess and query tokes don't match");
            let body = r#"<!DOCTYPE html>
<html>
  <head></head>
  <body>
    <p>invalid</p>
  </body>
</html>
"#;

            return resp
                .body(body.to_owned())
                .map_err(|e| warp::reject::custom(Error::new(format!("{}", e), vec![])));
        }

        let enc = key.encrypt(path_parts.as_bytes());

        let data_str = key
            .decrypt(&enc)
            .map_err(|e| HttpError::new(500, format!("failed to decrypt: {}", e), vec![]))
            .and_then(|decrypted_data| {
                String::from_utf8(decrypted_data).map_err(|e| {
                    HttpError::new(
                        500,
                        format!("failed to convert decrypted bytes to a string: {}", e),
                        vec![],
                    )
                })
            });

        let body = match data_str {
            Ok(s) => {
                r#"<!DOCTYPE html>
<html>
  <head></head>
  <body>
    <p>"#
                    .to_owned()
                    + &s
                    + r#"</p>
  </body>
</html>
"#
            }
            Err(_) => r#"<!DOCTYPE html>
<html>
  <head></head>
  <body>
    <p>invalid</p>
  </body>
</html>
"#
            .to_owned(),
        };

        Response::builder()
            .status(StatusCode::OK)
            .body(body)
            .map_err(|e| warp::reject::custom(Error::new(format!("{}", e), vec![])))
    }
}

mod models {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct EncryptResponse {
        pub data: String,
    }

    #[derive(Debug, Deserialize)]
    pub struct SecureOptions {
        pub token: Option<String>,
    }
}
