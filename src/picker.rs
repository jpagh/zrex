mod prompt;

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures_util::{StreamExt, future::join_all, stream::FuturesUnordered};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::time::{Instant, timeout_at};
use unicode_width::UnicodeWidthStr;

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
    label: String,
    title: String,
    status: String,
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

    let targets: Vec<_> = choices.iter().map(|(_, target)| target).collect();
    if let Some(index) = prompt::select(&targets)? {
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
    let mut views: FuturesUnordered<_> = entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            let id = session::id_of(entry);
            if id.is_empty() {
                return None;
            }
            let reply = session::start_view(&mut ctrl, &id);
            Some(async move {
                let view = optional_reply(deadline, reply).await?;
                Some((index, targets(&server.name, entry, &id, &view)))
            })
        })
        .collect();
    let mut missing_views = 0;
    let mut pending = Vec::new();
    while let Some(view) = views.next().await {
        if let Some((index, targets)) = view {
            // Start metadata queries as soon as this session's view arrives,
            // without waiting for other views or extending the server deadline.
            pending.push(describe_targets(&mut ctrl, deadline, index, targets));
        } else {
            missing_views += 1;
        }
    }
    let mut groups = join_all(pending).await;
    groups.sort_unstable_by_key(|(index, _)| *index);
    Ok((
        groups
            .into_iter()
            .flat_map(|(_, targets)| targets)
            .collect(),
        missing_views,
    ))
}

type Reply = Result<tokio::sync::oneshot::Receiver<Result<Value>>>;

async fn optional_reply(deadline: Instant, reply: Reply) -> Option<Value> {
    timeout_at(deadline, reply.ok()?).await.ok()?.ok()?.ok()
}

fn describe_targets(
    ctrl: &mut Control,
    deadline: Instant,
    index: usize,
    mut targets: Vec<Target>,
) -> impl Future<Output = (usize, Vec<Target>)> + use<> {
    let mut requests = HashMap::new();
    for target in &targets {
        // Session, window, and split rows can all point to the same block.
        requests.entry(target.block_id.clone()).or_insert_with(|| {
            let payload = json!({"session_id": target.session_id, "block_id": target.block_id});
            let title = ctrl.start_call("com.superlogical.terminal.title", payload.clone());
            let status = ctrl.start_call("com.superlogical.terminal.program_status", payload);
            (title, status)
        });
    }
    async move {
        let details: HashMap<_, _> = join_all(requests.into_iter().map(
            |(id, (title, status))| async move {
                let (title, status) = tokio::join!(
                    optional_reply(deadline, title),
                    optional_reply(deadline, status)
                );
                let title = title
                    .as_ref()
                    .map_or_else(String::new, |reply| clean_json_field(reply, "title", 64));
                let status = status.as_ref().and_then(status_summary);
                (id, (title, status))
            },
        ))
        .await
        .into_iter()
        .collect();
        for target in &mut targets {
            if let Some((title, status)) = details.get(&target.block_id) {
                target.title.clone_from(title);
                if let Some(status) = status {
                    target.status.clone_from(status);
                }
            }
        }
        (index, targets)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ProgramState {
    Blocked,
    Error,
    Working,
    Done,
    Idle,
}

impl ProgramState {
    fn from_str(state: &str) -> Self {
        match state {
            "blocked" => Self::Blocked,
            "error" => Self::Error,
            "working" => Self::Working,
            "done" => Self::Done,
            _ => Self::Idle,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::Error => "error",
            Self::Working => "working",
            Self::Done => "done",
            Self::Idle => "idle",
        }
    }

    fn shows_kind(self) -> bool {
        self == Self::Blocked
    }

    fn shows_progress(self) -> bool {
        matches!(self, Self::Working | Self::Blocked)
    }
}

fn status_summary(reply: &Value) -> Option<String> {
    let records = reply.get("records")?.as_array()?;
    // Surface the record most likely to need attention. Keep the server's
    // root-first order when records have the same priority.
    let (record, state) = records
        .iter()
        .filter_map(|record| {
            let state = ProgramState::from_str(record.get("state")?.as_str()?);
            Some((record, state))
        })
        .min_by_key(|(_, state)| *state)?;
    let app = clean_json_field(record, "effective_app", 24);
    let app = if app.is_empty() {
        clean_json_field(record, "app", 24)
    } else {
        app
    };
    let mut summary = if app.is_empty() {
        state.label().to_owned()
    } else {
        format!("{} {app}", state.label())
    };
    if state.shows_kind()
        && let Some(kind @ ("permission" | "question" | "auth")) =
            record.get("kind").and_then(Value::as_str)
    {
        summary.push_str(&format!(" ({kind})"));
    }
    if state.shows_progress()
        && let Some(progress @ 0..=100) = record.get("progress").and_then(Value::as_u64)
    {
        summary.push_str(&format!(" {progress}%"));
    }
    let title = clean_json_field(record, "title", 40);
    let message = clean_json_field(record, "msg", 50);
    for detail in [&title, &message]
        .into_iter()
        .filter(|detail| !detail.is_empty())
    {
        summary.push_str(": ");
        summary.push_str(detail);
    }
    Some(summary)
}

fn clean_json_field(value: &Value, key: &str, max_chars: usize) -> String {
    let clean = one_line(value.get(key).and_then(Value::as_str).unwrap_or_default());
    let mut chars = clean.chars();
    let mut short: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        short.pop();
        short.push('…');
    }
    short
}

fn targets(server: &str, entry: &Value, session_id: &str, view: &Value) -> Vec<Target> {
    let session = format!(
        "[{}] {}",
        one_line(server),
        label_or_id(session::label_of(entry), session_id)
    );
    let mut targets = Vec::new();
    let mut add = |label: String, block_id: &str| {
        targets.push(Target {
            label,
            title: String::new(),
            status: String::new(),
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

impl Target {
    fn row(&self, columns: usize) -> String {
        let parts = [
            ("", &self.label),
            (" — ", &self.title),
            (" · ", &self.status),
        ];
        let mut parts: Vec<_> = parts
            .into_iter()
            .filter(|(_, text)| !text.is_empty())
            .map(|(separator, text)| (separator, text, 0))
            .collect();
        // Share display space across the label, title, and status.
        let separators: usize = parts
            .iter()
            .map(|(separator, _, _)| separator.width())
            .sum();
        let budget = columns.saturating_sub(separators);
        for _ in 0..budget {
            let Some((_, _, limit)) = parts
                .iter_mut()
                .filter(|(_, text, limit)| *limit < text.len())
                .min_by_key(|(_, _, limit)| *limit)
            else {
                break;
            };
            *limit += 1;
        }
        let mut row = String::new();
        for (separator, text, limit) in parts {
            if limit == 0 {
                continue;
            }
            row.push_str(separator);
            if text.len() <= limit {
                row.push_str(text);
            } else {
                let marker = if limit >= 3 { "…" } else { "." };
                let cutoff = text.floor_char_boundary(limit - marker.len());
                row.push_str(&text[..cutoff]);
                row.push_str(marker);
            }
        }
        row
    }
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
    fn status_summary_picks_highest_priority_and_formats_details() {
        let reply = json!({
            "records": [
                {"state": "working", "app": "cargo", "progress": 42, "title": "build"},
                {"state": "blocked", "app": "claude", "effective_app": "claude-code", "kind": "permission", "progress": 80, "title": "shell", "msg": "allow\nrun?"},
                {"state": "blocked", "app": "other", "kind": "question"}
            ]
        });
        assert_eq!(
            status_summary(&reply).as_deref(),
            Some("blocked claude-code (permission) 80%: shell: allow run?")
        );

        let fallback = json!({
            "records": [
                {"state": "done", "app": "pytest", "progress": 100, "kind": "permission", "msg": "ok"}
            ]
        });
        // Progress and kind are omitted for non-working/non-blocked states.
        assert_eq!(
            status_summary(&fallback).as_deref(),
            Some("done pytest: ok")
        );

        assert_eq!(status_summary(&json!({"records": []})), None);
    }

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
            .map(|t| (t.label.as_str(), t.block_id.as_str()))
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
