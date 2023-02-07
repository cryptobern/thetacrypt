use std::{fs, net::IpAddr, path::PathBuf};
use std::{process::exit, str::FromStr};

use log::{error, info};

use protocols::confgen::{self, cli};
use protocols::dirutil;

fn main() {
    env_logger::init();

    let cli = cli::parse();
    let ips = match ips_from_file(&cli.ip_file) {
        Ok(ips) => ips,
        Err(e) => {
            error!("{}", e);
            exit(1);
        }
    };

    match dirutil::ensure_sane_output_directory(&cli.outdir, false) {
        Ok(_) => info!("Using output directory: {}", &cli.outdir.display()),
        Err(e) => {
            error!("Invalid output directory: {}, aborting...", e,);
            exit(1);
        }
    }

    match confgen::run(
        ips,
        cli.rpc_port,
        cli.p2p_port,
        cli.port_mapping_strategy,
        cli.shuffle_peers,
        cli.listen_address,
        cli.outdir,
    ) {
        Ok(_) => {
            info!("Config generation successful, all config files saved to disk");
        }
        Err(e) => {
            error!("Config generation failed: {}", e);
            exit(1);
        }
    }
}

fn ips_from_file(path: &PathBuf) -> Result<Vec<String>, String> {
    let input = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => return Err(format!("Error reading IPs: {}", e)),
    };
    let lines = input.lines();

    let mut ips = Vec::new();
    for line in lines {
        match IpAddr::from_str(line) {
            Ok(_) => {
                ips.push(line.to_string());
            }
            Err(e) => {
                return Err(format!(
                    "Error reading IPs from file. {} was not a valid IP: {}",
                    line, e
                ))
            }
        }
    }

    Ok(ips)
}
