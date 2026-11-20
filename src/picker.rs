use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use dialoguer::{FuzzySelect, console::Term};
use futures_util::future::join_all;
use serde::Deserialize;
use serde_json::Value;
use tokio::time::{Instant, timeout_at};

use crate::app;
use crate::rex::{ServerAddress, ServerConfig, control::Control};
use crate::session;

const DISCOVERY_TIME: Duration = Duration::from_secs(3);

#[derive(Default, Deserialize)]
struct Config {
    #[serde(default)]
    servers: BTreeMap<String, String>,
}

struct Server {
    name: String,
    address: ServerAddress,
}

struct Target {
    display: String,
    session_id: String,
    block_id: String,
}

pub async fn run(server_config: &ServerConfig) -> Result<()> {
    app::ensure_terminal()?;
    let (servers, discover_local) = load_servers(server_config)?;
    let deadline = Instant::now() + DISCOVERY_TIME;

    // Resolve and query the default local server in parallel with saved servers
    // so a hung local socket never delays remote discovery.
    let local_future = async {
        if !discover_local {
            return Ok(None);
        }
        let address = timeout_at(deadline, ServerAddress::local_or_loopback())
            .await
            .context("local server detection timed out")?;
        if servers.iter().any(|server| server.address == address) {
            return Ok(None);
        }
        let server = Server {
            name: "local".to_owned(),
            address,
        };
        let result = discover_until(&server, deadline).await;
        Ok::<_, anyhow::Error>(Some((server, result)))
    };

    let (local_outcome, discovered) = tokio::join!(
        local_future,
        join_all(
            servers
                .iter()
                .map(|server| discover_until(server, deadline))
        )
    );

    let mut all_servers = Vec::with_capacity(servers.len() + 1);
    let mut all_results = Vec::with_capacity(servers.len() + 1);
    match local_outcome {
        Ok(Some((server, result))) => {
            all_servers.push(server);
            all_results.push(result);
        }
        Ok(None) => {}
        Err(error) => eprintln!("zrex pick: {}", one_line(&format!("{error:#}"))),
    }
    all_servers.extend(servers);
    all_results.extend(discovered);

    let mut choices = Vec::new();
    for (server, result) in all_servers.iter().zip(all_results) {
        match result {
            Ok((targets, missing_views)) => {
                if missing_views > 0 {
                    eprintln!(
                        "zrex pick: {}: could not list windows for {missing_views} session(s)",
                        one_line(&server.name)
                    );
                }
                choices.extend(targets.into_iter().map(|target| (server, target)));
            }
            Err(error) => eprintln!(
                "zrex pick: {}: {}",
                one_line(&server.name),
                one_line(&format!("{error:#}"))
            ),
        }
    }
    if choices.is_empty() {
        bail!("no attachable sessions found");
    }

    // FuzzySelect identifies the chosen item by its display string. Keep each
    // row unique even when the same server has sessions with identical labels.
    let mut seen = HashSet::new();
    let rows: Vec<_> = choices
        .iter()
        .map(|(_, target)| {
            let mut row = target.display.clone();
            let mut copy = 2;
            while !seen.insert(row.clone()) {
                row = format!("{} ({copy})", target.display);
                copy += 1;
            }
            row
        })
        .collect();
    let term = Term::stdout();
    let selected = FuzzySelect::new()
        .with_prompt("Attach (Esc to cancel)")
        .default(0)
        .report(false)
        .items(&rows)
        .interact_on_opt(&term);
    if selected.is_err() {
        let _ = term.show_cursor();
    }
    if let Some(index) = selected? {
        let (server, target) = &choices[index];
        app::attach_existing(&server.address, &target.session_id, &target.block_id).await?;
    }
    Ok(())
}

fn load_servers(server_config: &ServerConfig) -> Result<(Vec<Server>, bool)> {
    if let ServerConfig::Explicit(address) = server_config {
        return Ok((
            vec![Server {
                name: address.clone(),
                address: address.parse()?,
            }],
            false,
        ));
    }

    let config = config_path()
        .as_deref()
        .map(read_config)
        .transpose()?
        .unwrap_or_default();
    let mut servers = Vec::<Server>::new();
    for (name, address) in config.servers {
        match address.parse() {
            Ok(address) => servers.push(Server { name, address }),
            Err(error) => eprintln!(
                "zrex pick: {}: {}",
                one_line(&name),
                one_line(&format!("{error:#}"))
            ),
        }
    }

    match server_config {
        ServerConfig::Explicit(_) => unreachable!(),
        ServerConfig::Env(address) => {
            match address.parse() {
                Ok(address) if !servers.iter().any(|server| server.address == address) => {
                    servers.insert(
                        0,
                        Server {
                            name: "REX_SERVER".to_owned(),
                            address,
                        },
                    );
                }
                Ok(_) => {}
                Err(error) => eprintln!("zrex pick: {}", one_line(&format!("{error:#}"))),
            }
            Ok((servers, false))
        }
        ServerConfig::Default => Ok((servers, true)),
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

async fn discover_until(server: &Server, deadline: Instant) -> Result<(Vec<Target>, usize)> {
    let (mut ctrl, entries) = timeout_at(deadline, async {
        let (mut ctrl, _events) = Control::connect(&server.address, None).await?;
        let entries = session::list_all(&mut ctrl).await?;
        Ok::<_, anyhow::Error>((ctrl, entries))
    })
    .await
    .context("discovery timed out")??;

    // Send all view requests before waiting, so one slow session does not
    // prevent other sessions on the same server from appearing.
    let views = entries.iter().filter_map(|entry| {
        let id = session::id_of(entry);
        if id.is_empty() {
            return None;
        }
        let reply = session::start_view(&mut ctrl, &id);
        Some(async move {
            let reply = reply.ok()?;
            let view = timeout_at(deadline, reply).await.ok()?.ok()?.ok()?;
            Some(targets(&server.name, entry, &id, &view))
        })
    });
    let views = join_all(views).await;
    let missing_views = views.iter().filter(|view| view.is_none()).count();
    Ok((
        views.into_iter().flatten().flatten().collect(),
        missing_views,
    ))
}

fn targets(server: &str, entry: &Value, session_id: &str, view: &Value) -> Vec<Target> {
    let session = format!(
        "[{}] {}",
        one_line(server),
        label_or_id(session::label_of(entry), session_id)
    );
    let mut targets = Vec::new();
    let mut add = |display: String, block_id: &str| {
        targets.push(Target {
            display,
            session_id: session_id.to_owned(),
            block_id: block_id.to_owned(),
        });
    };
    if let Some(block_id) = session::block_of(view, None, None) {
        add(session.clone(), &block_id);
    }
    let windows = session::windows(view);
    for (index, window) in windows.iter().enumerate() {
        let number = index + 1;
        let name = format!(
            "{session} / {number} {}",
            label_or_id(&window.label, &window.id)
        );
        if let Some(block_id) = window
            .active_block_id
            .as_deref()
            .or_else(|| window.blocks.first().map(|block| block.id.as_str()))
        {
            add(name.clone(), block_id);
        }
        if window.blocks.len() > 1 {
            for (index, block) in window.blocks.iter().enumerate() {
                add(
                    format!(
                        "{name} / {number}.{} {}",
                        index + 1,
                        label_or_id(&block.label, &block.id)
                    ),
                    &block.id,
                );
            }
        }
    }
    targets
}

fn label_or_id(label: &str, id: &str) -> String {
    let label = one_line(label);
    if label.is_empty() {
        one_line(id)
    } else {
        label
    }
}

// Server-provided labels must not send terminal escapes or insert new rows.
fn one_line(text: &str) -> String {
    text.chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>()
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn targets_include_session_windows_and_splits() {
        let entry = json!({"session_id": "session:1", "label": "work"});
        let view = json!({
            "active_window_id": "window:1",
            "windows": [
                {
                    "window_id": "window:1",
                    "label": "dev",
                    "focused_block_id": "block:2",
                    "layers": [{
                        "blocks": [
                            {"block_id": "block:1", "label": "editor"},
                            {"block_id": "block:2", "label": ""}
                        ]
                    }]
                },
                {
                    "window_id": "window:2",
                    "label": "",
                    "layers": [{
                        "blocks": [
                            {"block_id": "block:3", "label": "logs"}
                        ]
                    }]
                }
            ]
        });
        let list = targets("office", &entry, "session:1", &view);
        let pairs: Vec<_> = list
            .iter()
            .map(|t| (t.display.as_str(), t.block_id.as_str()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("[office] work", "block:2"),
                ("[office] work / 1 dev", "block:2"),
                ("[office] work / 1 dev / 1.1 editor", "block:1"),
                ("[office] work / 1 dev / 1.2 block:2", "block:2"),
                ("[office] work / 2 window:2", "block:3"),
            ]
        );
    }

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
