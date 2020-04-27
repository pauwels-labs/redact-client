use config::{Config, ConfigError, Value};
use serde::Deserialize;
use std::collections::HashMap;

pub trait Configurator {
    fn get<'de, T: Deserialize<'de>>(&'de self, key: &'de str) -> Result<T, ConfigError>;
    fn get_str(&self, key: &str) -> Result<String, ConfigError>;
    fn get_int(&self, key: &str) -> Result<i64, ConfigError>;
    fn get_float(&self, key: &str) -> Result<f64, ConfigError>;
    fn get_bool(&self, key: &str) -> Result<bool, ConfigError>;
    fn get_table(&self, key: &str) -> Result<HashMap<String, Value>, ConfigError>;
    fn get_array(&self, key: &str) -> Result<Vec<Value>, ConfigError>;
}

pub fn new() -> Result<impl Configurator, ConfigError> {
    Config::default()
        .merge(config::Environment::with_prefix("REDACT").separator("_"))?
        .merge(config::File::with_name("config"))
        .map(|c| c.to_owned())
}

impl Configurator for Config {
    fn get<'de, T: Deserialize<'de>>(&'de self, key: &'de str) -> Result<T, ConfigError> {
        Config::get(self, key)
    }
    fn get_str(&self, key: &str) -> Result<String, ConfigError> {
        Config::get_str(self, key)
    }
    fn get_int(&self, key: &str) -> Result<i64, ConfigError> {
        Config::get_int(self, key)
    }
    fn get_float(&self, key: &str) -> Result<f64, ConfigError> {
        Config::get_float(self, key)
    }
    fn get_bool(&self, key: &str) -> Result<bool, ConfigError> {
        Config::get_bool(self, key)
    }
    fn get_table(&self, key: &str) -> Result<HashMap<String, Value>, ConfigError> {
        Config::get_table(self, key)
    }
    fn get_array(&self, key: &str) -> Result<Vec<Value>, ConfigError> {
        Config::get_array(self, key)
    }
}
