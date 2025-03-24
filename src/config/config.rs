use crate::config::app_params::*;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub listen: Listen,
    pub app: AppParams,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum Listen {
    Tcp { addr: String },
    Unix { path: String },
}

impl Config {
    pub fn from_file(path: &str) -> Self {
        let config_str = fs::read_to_string(path).expect("Failed to read configuration file");

        let mut config: Config = toml::from_str(&config_str).expect("Invalid configuration format");

        config.app.js_challenge_template =
            fs::read_to_string(&config.app.js_challenge_template_path)
                .expect("Failed to load JS challenge template");

        config
    }
}
