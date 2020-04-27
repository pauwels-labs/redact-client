use super::error::Error;
use sodiumoxide::crypto::hash::sha512;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use warp::filters::{cookie, BoxedFilter};
use warp::Filter;

pub fn gen_token() -> Result<String, Error> {
    let now = SystemTime::now();
    let epoch = now
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::new(format!("failed to get unix timestamp: {}", e), vec![]))?
        .as_millis();
    let token_uuid = Uuid::new_v4();
    let token_str = epoch.to_string() + " " + &token_uuid.to_string();
    let digest = sha512::hash(token_str.as_bytes());

    Ok(base64::encode_config(digest.0.to_vec(), base64::URL_SAFE))
}

pub fn gen_sid() -> String {
    base64::encode_config(Uuid::new_v4().to_string(), base64::URL_SAFE)
}

pub fn get_session(sess_mgr: Arc<Mutex<SessionManager>>) -> BoxedFilter<(Arc<Mutex<Session>>,)> {
    cookie::optional("sid")
        .map(move |sid: Option<String>| {
            let mut sess_mgr = sess_mgr.lock().unwrap();
            sid.and_then(|s| sess_mgr.get(&s))
                .or_else(|| sess_mgr.create())
        })
        .and_then(|sess: Option<Arc<Mutex<Session>>>| async {
            sess.map_or_else(
                || {
                    Err(warp::reject::custom(Error::new(
                        "cannot create session".to_owned(),
                        vec![],
                    )))
                },
                |s| Ok(s),
            )
        })
        .boxed()
}

pub struct Session {
    pub id: String,
    body: HashMap<String, Vec<String>>,
}

impl Session {
    pub fn insert(&mut self, path: &str, token: &str) {
        match self.body.get_mut(path) {
            Some(v) => {
                v.push(token.to_owned());
            }
            None => {
                self.body.insert(path.to_owned(), vec![token.to_owned()]);
            }
        }
    }

    pub fn consume(&mut self, path: &str, token: &str) -> Option<String> {
        let tokens = self.body.get_mut(path)?;
        let mut token_idx = None;
        for (i, t) in tokens.iter().enumerate() {
            if t == token {
                token_idx = Some(i);
                break;
            }
        }
        match token_idx {
            Some(t) => Some(tokens.remove(t)),
            _ => None,
        }
    }
}

pub struct SessionManager {
    sessions: HashMap<String, Arc<Mutex<Session>>>,
}

impl SessionManager {
    pub fn new() -> SessionManager {
        SessionManager {
            sessions: HashMap::new(),
        }
    }

    pub fn get(&self, sid: &str) -> Option<Arc<Mutex<Session>>> {
        self.sessions.get(sid).and_then(|s| Some(s.clone()))
    }

    pub fn create(&mut self) -> Option<Arc<Mutex<Session>>> {
        let sid = gen_sid();
        let sess = Session {
            id: sid.clone(),
            body: HashMap::new(),
        };

        self.sessions
            .insert(sid.clone(), Arc::new(Mutex::new(sess)));
        self.get(&sid)
    }
}
