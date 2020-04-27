use std::collections::HashMap;
use std::fmt::{Display, Formatter, Result};
use warp::reject::Reject;

#[derive(Debug)]
pub struct Error {
    msg: String,
    fields: HashMap<String, String>,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let mut fields_str = Vec::new();
        for (k, v) in self.fields.iter() {
            fields_str.push(format!("{}: {}", k, v));
        }

        if fields_str.len() > 0 {
            write!(f, "{}, {}", self.msg, fields_str.join(", "))
        } else {
            write!(f, "{}", self.msg)
        }
    }
}

impl Error {
    pub fn new(msg: String, fields: Vec<String>) -> Error {
        let mut hm: HashMap<String, String> = HashMap::new();
        let keys = fields.iter().enumerate().filter(|(i, _)| i % 2 == 0);
        let values = fields.iter().enumerate().filter(|(i, _)| i % 2 != 0);
        for ((_, k), (_, v)) in keys.zip(values) {
            hm.insert(k.to_owned(), v.to_owned());
        }

        Error {
            msg: msg,
            fields: hm,
        }
    }
}

impl Reject for Error {}
