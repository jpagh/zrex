use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::clean_one_line;
use crate::rex::ServerAddress;

pub const DISCOVERY_TIME: Duration = Duration::from_secs(3);

#[derive(Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub servers: BTreeMap<String, String>,
}

pub struct Server {
    pub name: String,
    pub address: ServerAddress,
}

pub struct SavedServers {
    pub servers: Vec<Server>,
    pub configured: usize,
}

pub fn load_saved_servers(command: &str) -> Result<SavedServers> {
    let config = config_path()
        .as_deref()
        .map(read_config)
        .transpose()?
        .unwrap_or_default();
    Ok(parse_saved_servers(config, command))
}

fn parse_saved_servers(config: Config, command: &str) -> SavedServers {
    let configured = config.servers.len();
    let mut servers = Vec::with_capacity(configured);
    for (name, address) in config.servers {
        match address.parse() {
            Ok(address) => servers.push(Server { name, address }),
            Err(error) => eprintln!(
                "zrex {command}: {}: {}",
                clean_one_line(&name),
                clean_one_line(&format!("{error:#}"))
            ),
        }
    }
    SavedServers {
        servers,
        configured,
    }
}

fn config_path() -> Option<PathBuf> {
    env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| env::home_dir().map(|home| home.join(".config")))
        .map(|dir| dir.join("zrex/config.toml"))
}

fn read_config(path: &Path) -> Result<Config> {
    match fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).with_context(|| format!("invalid {}", path.display())),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(Config::default()),
        Err(error) => Err(error).with_context(|| format!("could not read {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_config_parses_servers_and_handles_missing_file() {
        let missing = env::temp_dir().join(format!("zrex-missing-{}.toml", std::process::id()));
        assert!(read_config(&missing).unwrap().servers.is_empty());

        let path = env::temp_dir().join(format!("zrex-config-{}.toml", std::process::id()));
        fs::write(
            &path,
            "[servers]\noffice = \"https://office.example\"\nlab = \"http://127.0.0.1:7297\"\n",
        )
        .unwrap();
        let config = read_config(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(config.servers.len(), 2);
        assert_eq!(config.servers["office"], "https://office.example");
        assert_eq!(config.servers["lab"], "http://127.0.0.1:7297");
    }
}
