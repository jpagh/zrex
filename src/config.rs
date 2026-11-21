use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::rex::ServerAddress;
use crate::rex::control::{Control, Events};
use crate::text::clean_one_line;

pub const DISCOVERY_TIME: Duration = Duration::from_secs(3);

#[derive(Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub servers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub name: String,
    pub address: ServerAddress,
}

pub struct SavedServers {
    pub servers: Vec<Server>,
    pub configured: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ResolvedServer {
    pub server: Server,
    pub named: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerConfig {
    Explicit(String),
    Env(String),
    Default,
}

impl ServerConfig {
    pub fn from_sources(flag: Option<String>, env: Option<String>) -> Self {
        if let Some(address) = flag {
            Self::Explicit(address)
        } else if let Some(address) = env.filter(|address| !address.is_empty()) {
            Self::Env(address)
        } else {
            Self::Default
        }
    }

    pub async fn connect(&self) -> Result<(ServerAddress, Control, Events)> {
        match self {
            Self::Explicit(target) | Self::Env(target) => {
                if !target.is_empty() && !target.contains("://") {
                    let config = load_config()?;
                    if is_builtin_local(&config, target) {
                        return Control::connect_local_if_running(&[])
                            .await
                            .ok_or_else(|| anyhow::anyhow!("local: server is not running"));
                    }
                    let server = resolve_server_in(&config, target).await?.server.address;
                    let (ctrl, events) = Control::connect(&server, None).await?;
                    return Ok((server, ctrl, events));
                }
                let server = resolve_server(target).await?.server.address;
                let (ctrl, events) = Control::connect(&server, None).await?;
                Ok((server, ctrl, events))
            }
            Self::Default => {
                let server = ServerAddress::local_or_loopback().await;
                let (ctrl, events) = Control::connect(&server, None).await?;
                Ok((server, ctrl, events))
            }
        }
    }
}

pub fn is_builtin_local(config: &Config, target: &str) -> bool {
    target.eq_ignore_ascii_case("local")
        && !config
            .servers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("local"))
}

pub fn load_config() -> Result<Config> {
    Ok(config_path()
        .as_deref()
        .map(read_config)
        .transpose()?
        .unwrap_or_default())
}

pub fn load_saved_servers(command: &str) -> Result<SavedServers> {
    Ok(parse_saved_servers(&load_config()?, command))
}

pub fn parse_saved_servers(config: &Config, command: &str) -> SavedServers {
    let configured = config.servers.len();
    let mut servers = Vec::with_capacity(configured);
    for (name, address) in &config.servers {
        match address.parse() {
            Ok(address) => servers.push(Server {
                name: name.clone(),
                address,
            }),
            Err(error) => eprintln!(
                "zrex {command}: {}: {}",
                clean_one_line(name),
                clean_one_line(&format!("{error:#}"))
            ),
        }
    }
    SavedServers {
        servers,
        configured,
    }
}

/// Resolves a `--server` / `REX_SERVER` value as a saved server name from
/// `config.toml`, `local`, or a direct server address. Explicit URLs containing
/// `://` are parsed without reading `config.toml`.
pub async fn resolve_server(target: &str) -> Result<ResolvedServer> {
    if target.is_empty() || target.contains("://") {
        return Ok(ResolvedServer {
            server: Server {
                name: target.to_owned(),
                address: target.parse()?,
            },
            named: false,
        });
    }
    let config = load_config()?;
    resolve_server_in(&config, target).await
}

pub async fn resolve_server_in(config: &Config, target: &str) -> Result<ResolvedServer> {
    resolve_server_with(config, target, ServerAddress::local_or_loopback).await
}

pub(crate) async fn resolve_server_with<F, Fut>(
    config: &Config,
    target: &str,
    local: F,
) -> Result<ResolvedServer>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ServerAddress>,
{
    if !target.is_empty() && !target.contains("://") {
        if let Some(server) = lookup_saved_server(config, target)? {
            return Ok(ResolvedServer {
                server,
                named: true,
            });
        }
        if target.eq_ignore_ascii_case("local") {
            return Ok(ResolvedServer {
                server: Server {
                    name: "local".to_owned(),
                    address: local().await,
                },
                named: true,
            });
        }
    }
    Ok(ResolvedServer {
        server: Server {
            name: target.to_owned(),
            address: target.parse()?,
        },
        named: false,
    })
}

fn lookup_saved_server(config: &Config, name: &str) -> Result<Option<Server>> {
    if let Some((key, raw)) = config.servers.get_key_value(name) {
        return Ok(Some(parse_named_server(key, raw)?));
    }
    let matches: Vec<_> = config
        .servers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .collect();
    match matches.as_slice() {
        [(key, raw)] => Ok(Some(parse_named_server(key, raw)?)),
        [] => Ok(None),
        many => {
            let names = many
                .iter()
                .map(|(key, _)| clean_one_line(key))
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "ambiguous server name {}; matches: {names}",
                clean_one_line(name)
            );
        }
    }
}

fn parse_named_server(key: &str, raw: &str) -> Result<Server> {
    let address = raw
        .parse()
        .with_context(|| format!("invalid address for saved server {}", clean_one_line(key)))?;
    Ok(Server {
        name: key.to_owned(),
        address,
    })
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

    fn sample_config(entries: &[(&str, &str)]) -> Config {
        Config {
            servers: entries
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    #[tokio::test]
    async fn resolves_saved_server_aliases_local_and_direct_addresses() {
        let config = sample_config(&[
            ("mac", "https://my-mac.tail.ts.net"),
            ("Office", "http://10.0.0.5:7297"),
            ("broken", "ftp://bad.example"),
        ]);
        let fake_local = || async { ServerAddress::Unix(PathBuf::from("/tmp/local.sock")) };

        // Exact alias match.
        assert_eq!(
            resolve_server_with(&config, "mac", fake_local)
                .await
                .unwrap(),
            ResolvedServer {
                server: Server {
                    name: "mac".to_owned(),
                    address: "https://my-mac.tail.ts.net".parse().unwrap(),
                },
                named: true,
            }
        );

        // Case-insensitive alias match keeps canonical config name.
        assert_eq!(
            resolve_server_with(&config, "office", fake_local)
                .await
                .unwrap(),
            ResolvedServer {
                server: Server {
                    name: "Office".to_owned(),
                    address: "http://10.0.0.5:7297".parse().unwrap(),
                },
                named: true,
            }
        );

        // Built-in `local` alias when not configured in config.toml.
        assert_eq!(
            resolve_server_with(&config, "local", fake_local)
                .await
                .unwrap(),
            ResolvedServer {
                server: Server {
                    name: "local".to_owned(),
                    address: ServerAddress::Unix(PathBuf::from("/tmp/local.sock")),
                },
                named: true,
            }
        );

        // Explicit `local` entry in config.toml overrides the built-in local alias.
        let custom_local = sample_config(&[("local", "http://127.0.0.1:9999")]);
        assert_eq!(
            resolve_server_with(&custom_local, "local", fake_local)
                .await
                .unwrap(),
            ResolvedServer {
                server: Server {
                    name: "local".to_owned(),
                    address: "http://127.0.0.1:9999".parse().unwrap(),
                },
                named: true,
            }
        );

        // Explicit URL with scheme parses directly without matching aliases.
        assert_eq!(
            resolve_server_with(&config, "https://direct.example", fake_local)
                .await
                .unwrap(),
            ResolvedServer {
                server: Server {
                    name: "https://direct.example".to_owned(),
                    address: "https://direct.example".parse().unwrap(),
                },
                named: false,
            }
        );

        // Bare host:port not in config falls back to ServerAddress parsing.
        assert_eq!(
            resolve_server_with(&config, "127.0.0.1:7297", fake_local)
                .await
                .unwrap(),
            ResolvedServer {
                server: Server {
                    name: "127.0.0.1:7297".to_owned(),
                    address: "http://127.0.0.1:7297".parse().unwrap(),
                },
                named: false,
            }
        );

        // Invalid address on the requested saved server surfaces a clear error.
        let err = resolve_server_with(&config, "broken", fake_local)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("saved server broken"));

        // Empty target errors cleanly.
        assert!(resolve_server_with(&config, "", fake_local).await.is_err());

        // Ambiguous case-insensitive match fails instead of silently picking one.
        let ambiguous = sample_config(&[
            ("mac", "https://mac1.example"),
            ("Mac", "https://mac2.example"),
        ]);
        let err = resolve_server_with(&ambiguous, "MAC", fake_local)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("ambiguous server name"));
        // Exact match still wins over case-insensitive collision.
        assert_eq!(
            resolve_server_with(&ambiguous, "mac", fake_local)
                .await
                .unwrap()
                .server
                .address,
            "https://mac1.example".parse().unwrap()
        );
    }

    #[tokio::test]
    async fn normalizes_saved_server_addresses_and_rejects_malformed_urls() {
        let config = sample_config(&[
            ("office", "https://OFFICE.EXAMPLE:443/"),
            ("loopback", "http://127.0.0.1:7297/"),
            ("bad_space", "http://bad host"),
            ("bad_port", "http://:7297"),
        ]);

        let saved = parse_saved_servers(&config, "ls");
        assert_eq!(saved.configured, 4);
        assert_eq!(
            saved.servers,
            vec![
                Server {
                    name: "loopback".to_owned(),
                    address: "127.0.0.1:7297".parse().unwrap(),
                },
                Server {
                    name: "office".to_owned(),
                    address: "https://office.example".parse().unwrap(),
                },
            ]
        );

        let fake_local = || async { "http://127.0.0.1:7297".parse().unwrap() };
        let resolved = resolve_server_with(&config, "office", fake_local)
            .await
            .unwrap();
        let direct = resolve_server_with(&config, "https://office.example", fake_local)
            .await
            .unwrap();
        assert_eq!(resolved.server.address, direct.server.address);
    }
}
