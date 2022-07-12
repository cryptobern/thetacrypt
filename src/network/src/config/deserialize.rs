use serde::Deserialize;
use std::{fs, process::exit};
use toml;

#[derive(Deserialize)]
pub struct Config {
    pub servers: Server,
}

#[derive(Deserialize)]
pub struct Server {
    pub ids: Vec<u32>,
    pub ips: Vec<String>,
    pub p2p_ports: Vec<u32>,
    pub rpc_ports: Vec<u32>,
    pub listen_address: String,
}

// load config file
pub fn load_config(path: String) -> Config {
    let contents = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("Could not read file `{}`", path);
            exit(1);
        }
    };

    let config: Config = match toml::from_str(&contents) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Unable to load data from `{}`", path);
            println!("################ {}", e);
            exit(1);
        }
    };
    return config;
}