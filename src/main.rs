mod app;
mod config;
mod picker;
mod rex;
mod session;

use std::collections::{HashMap, HashSet};
use std::env;
use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::future::join_all;
use serde_json::Value;
use tokio::time::{Instant, timeout, timeout_at};

use crate::config::{DISCOVERY_TIME, Server};
use crate::rex::control::Control;
use crate::rex::{ServerAddress, ServerConfig};

const USAGE: &str = "\
zrex: use a session on a Rex server from a terminal

Usage:
  zrex [--server ADDRESS] ls
  zrex [--server ADDRESS] pick
  zrex [--server ADDRESS] a|attach [SESSION] [--window SELECTOR] [--block SELECTOR]
  zrex [--server ADDRESS] kill SESSION
  zrex completion zsh|bash|fish
  zrex --version

The server address comes from --server, or from REX_SERVER. Without either, zrex
uses a local Rex server's Unix socket when one is running, and otherwise
http://127.0.0.1:7297. An address may be an HTTP(S) URL or a Unix socket URL
such as unix:///Users/you/Library/Application%20Support/rex/server.sock. a is
short for attach. SESSION is a label, a full ID, or the last four or more
characters of an ID. When no session matches, attach makes one with that label,
so the same command opens a session and returns to it later. Without SESSION,
attach uses the first session. --window, or -w, picks the window: its number from
one, its label, window.block (such as 1.2), or - for a new window with the label
Rex picks. A label that no window has makes a window with that label, with one
shell in it. --block, or -b, picks a block inside the window by its number from
one, its label, or its ID. Without --window the client shows the window the
session already has, and never changes it, leaving what Rex.app shows alone. ls lists every session, its windows, and any splits (1.1, 1.2, ...) with a star
on the active window and block, and the terminal title a window's focused block
reports beside the window's label. Without --server or REX_SERVER, ls also lists
saved servers from ~/.config/zrex/config.toml (or $XDG_CONFIG_HOME/zrex/config.toml)
and skips the local server when none is running. completion prints a shell
completion script that completes session labels, window numbers and labels, and
block numbers and labels from the live server. pick fuzzy-searches existing
sessions, windows, and splits on the default (when running) and saved servers
(~/.config/zrex/config.toml, or $XDG_CONFIG_HOME/zrex/config.toml). With --server
it searches only that address. Enter attaches, Ctrl-N creates a new session,
Ctrl-T creates a new window in a session, and Esc cancels.

While attached:
  Ctrl-backslash          detach, and leave the session running

Terminal output streams directly to your terminal, so your terminal's own
scrollback, mouse selection, and clipboard work as they always do.";

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Help,
    Version,
    List,
    Pick,
    Attach {
        target: Option<String>,
        window: Option<String>,
        block: Option<String>,
    },
    Kill {
        target: String,
    },
    Completion(Shell),
    Unknown(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Subcommand {
    List,
    Pick,
    Attach,
    Kill,
    Completion,
}

impl Subcommand {
    const COMPLETION_NAMES: [&str; 6] = ["a", "attach", "kill", "ls", "pick", "completion"];

    fn parse(name: &str) -> Option<Self> {
        match name {
            "ls" => Some(Self::List),
            "pick" => Some(Self::Pick),
            "a" | "attach" => Some(Self::Attach),
            "kill" => Some(Self::Kill),
            "completion" => Some(Self::Completion),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Shell {
    Zsh,
    Bash,
    Fish,
}

impl Shell {
    const NAMES: [&str; 3] = ["zsh", "bash", "fish"];

    fn parse(name: &str) -> Option<Self> {
        match name {
            "zsh" => Some(Self::Zsh),
            "bash" => Some(Self::Bash),
            "fish" => Some(Self::Fish),
            _ => None,
        }
    }

    fn script(&self) -> &'static str {
        match self {
            Self::Zsh => include_str!("../completions/zrex.zsh"),
            Self::Bash => include_str!("../completions/zrex.bash"),
            Self::Fish => include_str!("../completions/zrex.fish"),
        }
    }
}

#[derive(Clone, Copy)]
enum ValueOption {
    Server,
    Window,
    Block,
}

#[derive(Default)]
struct Arguments {
    server: Option<String>,
    command: Option<String>,
    target: Option<String>,
    window: Option<String>,
    block: Option<String>,
    pending: Option<ValueOption>,
    early_command: Option<Command>,
}

impl Arguments {
    /// A value flag at the end is an error for execution, but completion
    /// uses it to decide what kind of value to suggest.
    fn scan(args: impl IntoIterator<Item = String>) -> Result<Self> {
        let mut parsed = Self::default();
        for arg in args {
            if let Some(option) = parsed.pending.take() {
                let slot = match option {
                    ValueOption::Server => &mut parsed.server,
                    ValueOption::Window => &mut parsed.window,
                    ValueOption::Block => &mut parsed.block,
                };
                *slot = Some(arg);
                continue;
            }
            match arg.as_str() {
                "-h" | "--help" => parsed.early_command = Some(Command::Help),
                "-V" | "--version" => parsed.early_command = Some(Command::Version),
                "-S" | "--server" => parsed.pending = Some(ValueOption::Server),
                "-w" | "--window" => parsed.pending = Some(ValueOption::Window),
                "-b" | "--block" => parsed.pending = Some(ValueOption::Block),
                _ if parsed.command.is_none() => parsed.command = Some(arg),
                _ if parsed.target.is_none() => parsed.target = Some(arg),
                _ => anyhow::bail!("unexpected argument {arg}"),
            }
            if parsed.early_command.is_some() {
                break;
            }
        }
        Ok(parsed)
    }
}

fn parse_args(
    args: impl IntoIterator<Item = String>,
    env_server: Option<String>,
) -> Result<(ServerConfig, Command)> {
    let Arguments {
        server,
        command,
        target,
        window,
        block,
        pending,
        early_command,
    } = Arguments::scan(args)?;
    let server = ServerConfig::from_sources(server, env_server);
    if let Some(command) = early_command {
        return Ok((server, command));
    }
    match pending {
        Some(ValueOption::Server) => anyhow::bail!("--server needs an address"),
        Some(ValueOption::Window) => anyhow::bail!("--window needs a window number, a label, or -"),
        Some(ValueOption::Block) => {
            anyhow::bail!("--block needs a block number, a label, or an ID")
        }
        None => {}
    }
    let cmd = match command.as_deref() {
        Some(name) => match Subcommand::parse(name) {
            Some(Subcommand::List) => Command::List,
            Some(Subcommand::Pick) => {
                if target.is_some() || window.is_some() || block.is_some() {
                    anyhow::bail!("usage: zrex [--server ADDRESS] pick");
                }
                Command::Pick
            }
            Some(Subcommand::Attach) => Command::Attach {
                target,
                window,
                block,
            },
            Some(Subcommand::Kill) => match target {
                Some(target) => Command::Kill { target },
                None => anyhow::bail!("kill needs a session"),
            },
            Some(Subcommand::Completion) => match target.as_deref() {
                Some(other) => match Shell::parse(other) {
                    Some(shell) => Command::Completion(shell),
                    None => {
                        anyhow::bail!("no completion script for {other}; use zsh, bash, or fish")
                    }
                },
                None => anyhow::bail!("completion needs zsh, bash, or fish"),
            },
            None => Command::Unknown(name.to_owned()),
        },
        None => Command::Help,
    };
    Ok((server, cmd))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut args = env::args().skip(1);
    let first = args.next();
    if first.as_deref() == Some("__complete") {
        complete(args).await;
        return Ok(());
    }
    let (server_config, command) =
        parse_args(first.into_iter().chain(args), env::var("REX_SERVER").ok())?;

    match command {
        Command::Help => {
            println!("{USAGE}");
            Ok(())
        }
        Command::Version => {
            println!("zrex {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::List => list(&server_config).await,
        Command::Pick => picker::run(&server_config).await,
        Command::Attach {
            target,
            window,
            block,
        } => app::attach(&server_config.resolve().await?, target, window, block).await,
        Command::Kill { target } => kill(&server_config.resolve().await?, &target).await,
        Command::Completion(shell) => {
            print!("{}", shell.script());
            Ok(())
        }
        Command::Unknown(other) => {
            eprintln!("unknown command {other}\n\n{USAGE}");
            std::process::exit(2);
        }
    }
}

struct MultiListReport {
    groups: Vec<(String, Vec<String>)>,
    errors: Vec<String>,
    reachable: usize,
}

async fn list(server_config: &ServerConfig) -> Result<()> {
    match server_config {
        ServerConfig::Explicit(address) | ServerConfig::Env(address) => {
            let server = address.parse()?;
            list_single(&server).await
        }
        ServerConfig::Default => {
            let saved = config::load_saved_servers("ls")?;
            if saved.configured == 0 {
                let Some(server) = ServerAddress::local_if_running().await else {
                    println!("no sessions");
                    return Ok(());
                };
                return list_single(&server).await;
            }
            list_multi(saved.servers).await
        }
    }
}

async fn list_single(server: &ServerAddress) -> Result<()> {
    let (mut ctrl, _events) = Control::connect(server, None).await?;
    let sessions = session::list_all(&mut ctrl).await?;
    if sessions.is_empty() {
        println!("no sessions");
        return Ok(());
    }
    for line in format_sessions(&mut ctrl, sessions, None).await {
        println!("{line}");
    }
    Ok(())
}

async fn list_multi(servers: Vec<Server>) -> Result<()> {
    let deadline = Instant::now() + DISCOVERY_TIME;
    let report = collect_multi_list(servers, ServerAddress::local_if_running(), deadline).await;
    for error in report.errors {
        eprintln!("zrex ls: {error}");
    }
    if report.reachable == 0 {
        anyhow::bail!("no reachable servers");
    }
    if report.groups.is_empty() {
        println!("no sessions");
        return Ok(());
    }
    for (index, (name, lines)) in report.groups.iter().enumerate() {
        if index > 0 {
            println!();
        }
        println!("[{}]", clean_one_line(name));
        for line in lines {
            println!("{line}");
        }
    }
    Ok(())
}

async fn collect_multi_list(
    servers: Vec<Server>,
    local_probe: impl Future<Output = Option<ServerAddress>>,
    deadline: Instant,
) -> MultiListReport {
    let local_future = async {
        let Some(address) = timeout_at(deadline, local_probe)
            .await
            .context("local server detection timed out")?
        else {
            return Ok(None);
        };
        if servers.iter().any(|server| server.address == address) {
            return Ok(None);
        }
        let server = Server {
            name: "local".to_owned(),
            address,
        };
        let result = list_server_until(&server, deadline).await;
        Ok::<_, anyhow::Error>(Some((server, result)))
    };

    let (local_outcome, listed) = tokio::join!(
        local_future,
        join_all(
            servers
                .iter()
                .map(|server| list_server_until(server, deadline))
        )
    );

    let mut all_servers = Vec::with_capacity(servers.len() + 1);
    let mut all_results = Vec::with_capacity(servers.len() + 1);
    let mut errors = Vec::new();
    match local_outcome {
        Ok(Some((server, result))) => {
            all_servers.push(server);
            all_results.push(result);
        }
        Ok(None) => {}
        Err(error) => errors.push(clean_one_line(&format!("{error:#}"))),
    }
    all_servers.extend(servers);
    all_results.extend(listed);

    let mut groups = Vec::new();
    let mut reachable = 0;
    for (server, result) in all_servers.into_iter().zip(all_results) {
        match result {
            Ok(lines) => {
                reachable += 1;
                if !lines.is_empty() {
                    groups.push((server.name, lines));
                }
            }
            Err(error) => errors.push(format!(
                "{}: {}",
                clean_one_line(&server.name),
                clean_one_line(&format!("{error:#}"))
            )),
        }
    }

    MultiListReport {
        groups,
        errors,
        reachable,
    }
}

async fn list_server_until(server: &Server, deadline: Instant) -> Result<Vec<String>> {
    let (mut ctrl, sessions) = timeout_at(deadline, async {
        let (mut ctrl, _events) = Control::connect(&server.address, None).await?;
        let sessions = session::list_all(&mut ctrl).await?;
        Ok::<_, anyhow::Error>((ctrl, sessions))
    })
    .await
    .context("listing timed out")??;
    if sessions.is_empty() {
        return Ok(Vec::new());
    }
    Ok(format_sessions(&mut ctrl, sessions, Some(deadline)).await)
}

async fn format_sessions(
    ctrl: &mut Control,
    sessions: Vec<Value>,
    deadline: Option<Instant>,
) -> Vec<String> {
    let width = sessions
        .iter()
        .map(|session| session::label_of(session).chars().count())
        .max()
        .unwrap_or(0);
    let pending_views: Vec<_> = sessions
        .into_iter()
        .map(|entry| {
            let id = session::id_of(&entry);
            let reply = (!id.is_empty()).then(|| session::start_view(ctrl, &id));
            (entry, id, reply)
        })
        .collect();
    let views: Vec<_> = join_all(
        pending_views
            .into_iter()
            .map(|(entry, id, reply)| async move {
                let view = match reply {
                    Some(reply) => optional_call(reply, deadline).await,
                    None => None,
                };
                (entry, id, view)
            }),
    )
    .await;

    let mut pending_titles = Vec::with_capacity(views.len());
    for (entry, id, view) in views {
        let title_calls = match &view {
            Some(view) => start_window_titles(ctrl, &id, view),
            None => Vec::new(),
        };
        pending_titles.push((entry, view, title_calls));
    }

    let resolved: Vec<_> = join_all(pending_titles.into_iter().map(
        |(entry, view, title_calls)| async move {
            let titles = finish_window_titles(title_calls, deadline).await;
            (entry, view, titles)
        },
    ))
    .await;

    let mut lines = Vec::new();
    for (entry, view, titles) in resolved {
        lines.extend(format_session(&entry, view.as_ref(), width, &titles));
    }
    lines
}

type PendingWindowTitle = (String, session::PendingCall, Option<session::PendingCall>);

/// The tab title Rex.app shows comes from the terminal, not the window label.
fn start_window_titles(
    ctrl: &mut Control,
    session_id: &str,
    view: &Value,
) -> Vec<PendingWindowTitle> {
    let mut pending = Vec::new();
    for window in session::windows(view) {
        let Some(block_id) = window.focused_block_id else {
            continue;
        };
        if let Ok(title_reply) = session::start_terminal_title(ctrl, session_id, &block_id) {
            let process_reply = session::start_terminal_process(ctrl, session_id, &block_id).ok();
            pending.push((window.id, title_reply, process_reply));
        }
    }
    pending
}

async fn finish_window_titles(
    pending: Vec<PendingWindowTitle>,
    deadline: Option<Instant>,
) -> HashMap<String, String> {
    let resolved = join_all(pending.into_iter().map(
        |(window_id, title_reply, process_reply)| async move {
            let (title_reply, process_reply) =
                tokio::join!(optional_call(Ok(title_reply), deadline), async {
                    match process_reply {
                        Some(reply) => optional_call(Ok(reply), deadline).await,
                        None => None,
                    }
                });
            let title = title_reply
                .as_ref()
                .and_then(|reply| session::live_terminal_title(reply, process_reply.as_ref()))
                .map(str::to_owned);
            (window_id, title)
        },
    ))
    .await;
    resolved
        .into_iter()
        .filter_map(|(window_id, title)| Some((window_id, title?)))
        .collect()
}

async fn optional_call(
    call: Result<session::PendingCall>,
    deadline: Option<Instant>,
) -> Option<Value> {
    let rx = call.ok()?;
    match deadline {
        Some(deadline) => timeout_at(deadline, rx).await.ok()?.ok()?.ok(),
        None => rx.await.ok()?.ok(),
    }
}

fn format_session(
    entry: &Value,
    view: Option<&Value>,
    width: usize,
    titles: &HashMap<String, String>,
) -> Vec<String> {
    let id = session::id_of(entry);
    let mut lines = vec![format!("{:width$}  {id}", session::label_of(entry))];
    let Some(view) = view else {
        return lines;
    };
    let active = session::active_window_id(view);
    for (number, window) in session::windows(view).iter().enumerate() {
        let win_num = number + 1;
        let mark = if active == Some(window.id.as_str()) {
            "*"
        } else {
            " "
        };
        let title = titles
            .get(&window.id)
            .map(|title| clean_title(title))
            .unwrap_or_default();
        if title.is_empty() || title == window.label {
            lines.push(format!("  {mark} {win_num}  {}", window.label));
        } else {
            lines.push(format!("  {mark} {win_num}  {} — {title}", window.label));
        }
        if window.blocks.len() > 1 {
            for (b_idx, block) in window.blocks.iter().enumerate() {
                let b_mark = if window.active_block_id.as_deref() == Some(block.id.as_str()) {
                    "*"
                } else {
                    " "
                };
                lines.push(format!(
                    "    {b_mark} {win_num}.{}  {}",
                    b_idx + 1,
                    block.label
                ));
            }
        }
    }
    lines
}

async fn kill(server: &ServerAddress, target: &str) -> Result<()> {
    let (mut ctrl, _events) = Control::connect(server, None).await?;
    let id = session::pick(&mut ctrl, Some(target)).await?;
    session::destroy(&mut ctrl, &id).await?;
    println!("destroyed {id}");
    Ok(())
}

/// Server- and program-provided text must not send terminal escapes or span
/// multiple lines.
pub(crate) fn clean_one_line(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .trim()
        .to_owned()
}

pub(crate) fn clean_truncated(text: &str, max_chars: usize) -> String {
    let cleaned = clean_one_line(text);
    let mut chars = cleaned.chars();
    let mut short: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        short.pop();
        short.push('…');
    }
    short
}

fn clean_title(title: &str) -> String {
    clean_truncated(title, 80)
}

const COMPLETION_TIME: Duration = Duration::from_secs(2);

#[derive(Debug, PartialEq, Eq)]
enum Completion {
    Commands,
    Shells,
    Sessions,
    Flags {
        attach: bool,
    },
    Windows {
        session: Option<String>,
    },
    Blocks {
        session: Option<String>,
        window: Option<String>,
    },
    Nothing,
}

fn completion_context(current: &str, parsed: &Arguments) -> Completion {
    if parsed.early_command.is_some() {
        return Completion::Nothing;
    }
    match parsed.pending {
        Some(ValueOption::Server) => return Completion::Nothing,
        Some(ValueOption::Window) => {
            return Completion::Windows {
                session: parsed.target.clone(),
            };
        }
        Some(ValueOption::Block) => {
            return Completion::Blocks {
                session: parsed.target.clone(),
                window: parsed.window.clone(),
            };
        }
        None => {}
    }
    let subcommand = parsed.command.as_deref().map(Subcommand::parse);
    let attach = matches!(subcommand, Some(Some(Subcommand::Attach)));
    if current.starts_with('-') {
        return Completion::Flags { attach };
    }
    match subcommand {
        None => Completion::Commands,
        Some(Some(Subcommand::Completion)) if parsed.target.is_none() => Completion::Shells,
        Some(Some(Subcommand::Attach | Subcommand::Kill)) if parsed.target.is_none() => {
            Completion::Sessions
        }
        Some(Some(Subcommand::Attach)) => Completion::Flags { attach: true },
        Some(Some(
            Subcommand::Kill | Subcommand::List | Subcommand::Pick | Subcommand::Completion,
        )) => Completion::Flags { attach: false },
        Some(None) => Completion::Nothing,
    }
}

/// The shell passes the word being completed first, then the words before it.
async fn complete(mut args: impl Iterator<Item = String>) {
    let Some(current) = args.next() else {
        return;
    };
    let Ok(parsed) = Arguments::scan(args) else {
        return;
    };
    let candidates = match completion_context(&current, &parsed) {
        Completion::Nothing => return,
        Completion::Commands => Subcommand::COMPLETION_NAMES
            .into_iter()
            .map(str::to_owned)
            .collect(),
        Completion::Shells => Shell::NAMES.into_iter().map(str::to_owned).collect(),
        Completion::Flags { attach } => flags(attach),
        context => {
            let server_config =
                ServerConfig::from_sources(parsed.server, env::var("REX_SERVER").ok());
            let Ok(Some(candidates)) = timeout(COMPLETION_TIME, async {
                let server = match server_config {
                    ServerConfig::Default => ServerAddress::local_if_running().await?,
                    other => other.resolve().await.ok()?,
                };
                Some(match context {
                    Completion::Sessions => session_candidates(&server).await,
                    Completion::Windows { session } => {
                        window_candidates(&server, session.as_deref()).await
                    }
                    Completion::Blocks { session, window } => {
                        block_candidates(&server, session.as_deref(), window.as_deref()).await
                    }
                    _ => unreachable!(),
                })
            })
            .await
            else {
                return;
            };
            candidates
        }
    };
    let prefix = current.to_lowercase();
    for candidate in candidates {
        if candidate.to_lowercase().starts_with(&prefix) {
            println!("{candidate}");
        }
    }
}

fn flags(attach: bool) -> Vec<String> {
    let mut flags: Vec<String> = ["-S", "--server", "-h", "--help", "-V", "--version"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    if attach {
        flags.extend(["-w", "--window", "-b", "--block"].map(str::to_owned));
    }
    flags
}

async fn session_candidates(server: &ServerAddress) -> Vec<String> {
    let Ok((mut ctrl, _events)) = Control::connect(server, None).await else {
        return Vec::new();
    };
    let Ok(sessions) = session::list(&mut ctrl).await else {
        return Vec::new();
    };
    dedupe(
        sessions
            .iter()
            .map(|session| session::label_of(session).to_owned())
            .filter(|label| !label.is_empty())
            .collect(),
    )
}

async fn view_for(server: &ServerAddress, target: Option<&str>) -> Option<Value> {
    let (mut ctrl, _events) = Control::connect(server, None).await.ok()?;
    let sessions = session::list_all(&mut ctrl).await.ok()?;
    let session = session::select_session(&sessions, target)?;
    session::view(&mut ctrl, &session::id_of(session))
        .await
        .ok()
}

async fn window_candidates(server: &ServerAddress, target: Option<&str>) -> Vec<String> {
    let Some(view) = view_for(server, target).await else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    for (number, window) in session::windows(&view).into_iter().enumerate() {
        let number = number + 1;
        candidates.push(number.to_string());
        if !window.label.is_empty() {
            candidates.push(window.label.clone());
        }
        if window.blocks.len() > 1 {
            for block in 1..=window.blocks.len() {
                candidates.push(format!("{number}.{block}"));
            }
        }
    }
    dedupe(candidates)
}

async fn block_candidates(
    server: &ServerAddress,
    target: Option<&str>,
    window_selector: Option<&str>,
) -> Vec<String> {
    let Some(view) = view_for(server, target).await else {
        return Vec::new();
    };
    // Completion runs after an explicit --block flag, so a dotted window
    // label must resolve as-is, just as it will when the command runs.
    let windows = session::windows(&view);
    let Some(window) = session::select_window(&view, &windows, window_selector) else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    for (number, block) in window.blocks.iter().enumerate() {
        candidates.push((number + 1).to_string());
        if !block.label.is_empty() {
            candidates.push(block.label.clone());
        }
    }
    dedupe(candidates)
}

fn dedupe(items: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    items
        .into_iter()
        .filter(|item| seen.insert(item.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn pick_distinguishes_a_server_override_from_the_environment_default() {
        let env = Some("https://default.example".to_owned());
        assert_eq!(
            parse_args(args(&["pick"]), env.clone()).unwrap(),
            (
                ServerConfig::Env("https://default.example".to_owned()),
                Command::Pick
            )
        );
        assert_eq!(
            parse_args(args(&["pick", "-S", "https://only.example"]), env).unwrap(),
            (
                ServerConfig::Explicit("https://only.example".to_owned()),
                Command::Pick
            )
        );
        assert!(parse_args(args(&["pick", "--window", "1"]), None).is_err());
    }

    #[test]
    fn parses_cli_flags_and_commands() {
        let (server, cmd) = parse_args(args(&["ls"]), None).unwrap();
        assert_eq!(server, ServerConfig::Default);
        assert_eq!(cmd, Command::List);
        assert_eq!(
            parse_args(args(&["ls"]), Some(String::new())).unwrap().0,
            ServerConfig::Default
        );

        let (server, cmd) = parse_args(
            args(&["-S", "https://example.com", "a", "work", "-w", "1.2"]),
            Some("http://env:7297".to_owned()),
        )
        .unwrap();
        assert_eq!(
            server,
            ServerConfig::Explicit("https://example.com".to_owned())
        );
        assert_eq!(
            cmd,
            Command::Attach {
                target: Some("work".to_owned()),
                window: Some("1.2".to_owned()),
                block: None,
            }
        );

        let (_, cmd) = parse_args(
            args(&["attach", "work", "--window", "1", "--block", "2"]),
            None,
        )
        .unwrap();
        assert_eq!(
            cmd,
            Command::Attach {
                target: Some("work".to_owned()),
                window: Some("1".to_owned()),
                block: Some("2".to_owned()),
            }
        );

        let (server, cmd) =
            parse_args(args(&["kill", "work"]), Some("http://env:7297".to_owned())).unwrap();
        assert_eq!(server, ServerConfig::Env("http://env:7297".to_owned()));
        assert_eq!(
            cmd,
            Command::Kill {
                target: "work".to_owned()
            }
        );

        assert!(parse_args(args(&["kill"]), None).is_err());
        assert!(parse_args(args(&["-S"]), None).is_err());
        assert!(parse_args(args(&["-w"]), None).is_err());
        assert!(parse_args(args(&["-b"]), None).is_err());
        assert!(parse_args(args(&["a", "one", "two"]), None).is_err());

        assert_eq!(
            parse_args(args(&["completion", "zsh"]), None).unwrap().1,
            Command::Completion(Shell::Zsh)
        );
        assert!(parse_args(args(&["completion", "powershell"]), None).is_err());
        assert!(parse_args(args(&["completion"]), None).is_err());
    }

    #[test]
    fn completion_uses_the_last_server_and_consumes_flag_values() {
        let words = args(&[
            "--server",
            "http://first",
            "attach",
            "--window",
            "--server",
            "-S",
            "https://last",
            "--block",
            "--window",
        ]);
        let parsed = Arguments::scan(words.clone()).unwrap();
        assert_eq!(completion_context("", &parsed), Completion::Sessions);
        assert_eq!(parsed.server.as_deref(), Some("https://last"));
        assert_eq!(
            ServerConfig::from_sources(parsed.server, None),
            parse_args(words, None).unwrap().0
        );

        let parsed = Arguments::scan(args(&["attach", "--window", "--server"])).unwrap();
        assert_eq!(parsed.server, None);
        assert_eq!(completion_context("", &parsed), Completion::Sessions);
    }

    #[test]
    fn formats_sessions_windows_and_splits_for_ls() {
        let entry = json!({"session_id": "session:1", "label": "work"});
        let view = json!({
            "active_window_id": "window:1",
            "windows": [
                {
                    "window_id": "window:1",
                    "label": "Window one",
                    "focused_block_id": "block:2",
                    "zoomed_block_id": "block:1",
                    "layers": [{
                        "layer_id": "layer:1",
                        "blocks": [
                            {"block_id": "block:1", "label": "Block one"},
                            {"block_id": "block:2", "label": "Block two"},
                        ]
                    }]
                },
                {
                    "window_id": "window:2",
                    "label": "Window two",
                    "focused_block_id": "block:3",
                    "layers": [{
                        "layer_id": "layer:2",
                        "blocks": [
                            {"block_id": "block:3", "label": "Block three"},
                        ]
                    }]
                }
            ]
        });
        let windows = session::windows(&view);
        assert_eq!(windows[0].focused_block_id.as_deref(), Some("block:2"));
        let lines = format_session(&entry, Some(&view), 4, &HashMap::new());
        assert_eq!(
            lines,
            vec![
                "work  session:1",
                "  * 1  Window one",
                "    * 1.1  Block one",
                "      1.2  Block two",
                "    2  Window two",
            ]
        );

        let titles = HashMap::from([("window:1".to_owned(), "π - release".to_owned())]);
        let lines = format_session(&entry, Some(&view), 4, &titles);
        assert_eq!(lines[1], "  * 1  Window one — π - release");
        assert_eq!(lines[4], "    2  Window two");
    }

    #[test]
    fn cleans_a_terminal_title_before_printing_it() {
        assert_eq!(clean_title("  π - release  "), "π - release");
        assert_eq!(clean_title("a\x1b[2Jb"), "a [2Jb");
        assert_eq!(clean_title(&"x".repeat(100)).chars().count(), 80);
        assert_eq!(clean_title("\u{7}\u{9}"), "");
    }

    #[test]
    fn chooses_completion_from_the_words_so_far() {
        fn completion_context(current: &str, words: &[String]) -> Completion {
            super::completion_context(current, &Arguments::scan(words.iter().cloned()).unwrap())
        }
        assert_eq!(completion_context("", &[]), Completion::Commands);
        assert_eq!(completion_context("", &args(&["a"])), Completion::Sessions);
        assert_eq!(
            completion_context("", &args(&["kill"])),
            Completion::Sessions
        );
        assert_eq!(
            completion_context("", &args(&["a", "work", "-w"])),
            Completion::Windows {
                session: Some("work".to_owned())
            }
        );
        assert_eq!(
            completion_context("", &args(&["a", "work", "-w", "1", "-b"])),
            Completion::Blocks {
                session: Some("work".to_owned()),
                window: Some("1".to_owned())
            }
        );
        assert_eq!(
            completion_context("--w", &args(&["a", "work"])),
            Completion::Flags { attach: true }
        );
        assert_eq!(
            completion_context("--server", &[]),
            Completion::Flags { attach: false }
        );
        assert_eq!(
            completion_context("-", &[]),
            Completion::Flags { attach: false }
        );
        assert_eq!(
            completion_context("-", &args(&["a"])),
            Completion::Flags { attach: true }
        );
        assert_eq!(
            completion_context("-", &args(&["a", "work", "-w"])),
            Completion::Windows {
                session: Some("work".to_owned())
            }
        );
        assert_eq!(
            completion_context("", &args(&["completion"])),
            Completion::Shells
        );
        assert_eq!(
            completion_context("z", &args(&["completion"])),
            Completion::Shells
        );
        assert_eq!(
            completion_context("", &args(&["completion", "zsh"])),
            Completion::Flags { attach: false }
        );
        assert_eq!(
            completion_context("", &args(&["--server", "http://example.com"])),
            Completion::Commands
        );
        assert_eq!(
            completion_context("", &args(&["--server", "http://example.com", "a"])),
            Completion::Sessions
        );
        assert_eq!(
            completion_context("", &args(&["--server"])),
            Completion::Nothing
        );
    }

    async fn spawn_mock_ls_server(sessions: Value) -> ServerAddress {
        use futures_util::{SinkExt, StreamExt};
        use tokio::net::TcpListener;
        use tokio_tungstenite::accept_hdr_async;
        use tokio_tungstenite::tungstenite::Message;
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            #[allow(
                clippy::result_large_err,
                reason = "tungstenite fixes the callback error type"
            )]
            let mut ws = accept_hdr_async(stream, |req: &Request, mut res: Response| {
                if let Some(proto) = req.headers().get("Sec-WebSocket-Protocol") {
                    res.headers_mut()
                        .insert("Sec-WebSocket-Protocol", proto.clone());
                }
                Ok(res)
            })
            .await
            .unwrap();

            let _ = ws.next().await;
            ws.send(Message::text(
                json!({"type": "welcome", "api_revision": crate::rex::proto::API_REVISION})
                    .to_string(),
            ))
            .await
            .unwrap();

            while let Some(Ok(Message::Text(text))) = ws.next().await {
                let req: Value = serde_json::from_str(&text).unwrap();
                let id = req["id"].as_str().unwrap();
                let payload = match req["method"].as_str().unwrap() {
                    "session.attach_all" => json!({"sessions": sessions}),
                    "session.view" => json!({
                        "active_window_id": "window:1",
                        "windows": [{
                            "window_id": "window:1",
                            "label": "dev",
                            "focused_block_id": "block:1",
                            "layers": [{"blocks": [{"block_id": "block:1", "label": "shell"}]}]
                        }]
                    }),
                    "com.superlogical.terminal.title" => json!({"title": "vim"}),
                    "com.superlogical.terminal.process" => {
                        json!({"foreground": null, "child": null})
                    }
                    other => panic!("unexpected method {other}"),
                };
                ws.send(Message::text(
                    json!({"type": "response", "id": id, "seq": 0, "payload": payload}).to_string(),
                ))
                .await
                .unwrap();
            }
        });
        format!("http://{addr}").parse().unwrap()
    }

    #[tokio::test]
    async fn multi_list_skips_absent_local_lists_saved_servers_and_reports_saved_errors() {
        let office_addr =
            spawn_mock_ls_server(json!([{"session_id": "session:1", "label": "work"}])).await;
        let empty_addr = spawn_mock_ls_server(json!([])).await;

        let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr: ServerAddress = format!("http://{}", dead_listener.local_addr().unwrap())
            .parse()
            .unwrap();
        drop(dead_listener);

        let report = collect_multi_list(
            vec![
                Server {
                    name: "dead".to_owned(),
                    address: dead_addr,
                },
                Server {
                    name: "empty".to_owned(),
                    address: empty_addr,
                },
                Server {
                    name: "office".to_owned(),
                    address: office_addr,
                },
            ],
            async { None },
            Instant::now() + DISCOVERY_TIME,
        )
        .await;

        assert_eq!(report.reachable, 2);
        assert_eq!(report.errors.len(), 1);
        assert!(report.errors[0].starts_with("dead: "));
        assert_eq!(
            report.groups,
            vec![(
                "office".to_owned(),
                vec!["work  session:1".to_owned(), "  * 1  dev — vim".to_owned(),]
            )]
        );
    }

    #[tokio::test]
    async fn multi_list_includes_running_local_and_deduplicates_matching_saved_server() {
        let local_addr =
            spawn_mock_ls_server(json!([{"session_id": "session:0", "label": "home"}])).await;
        let office_addr =
            spawn_mock_ls_server(json!([{"session_id": "session:1", "label": "work"}])).await;

        let report = collect_multi_list(
            vec![Server {
                name: "office".to_owned(),
                address: office_addr,
            }],
            async { Some(local_addr) },
            Instant::now() + DISCOVERY_TIME,
        )
        .await;

        assert_eq!(report.reachable, 2);
        assert!(report.errors.is_empty());
        assert_eq!(report.groups.len(), 2);
        assert_eq!(report.groups[0].0, "local");
        assert_eq!(report.groups[1].0, "office");

        // When local matches a saved server address, it is listed once under the saved name.
        let shared_addr =
            spawn_mock_ls_server(json!([{"session_id": "session:2", "label": "lab"}])).await;
        let shared_copy: ServerAddress = match &shared_addr {
            ServerAddress::Network(url) => url.parse().unwrap(),
            ServerAddress::Unix(path) => ServerAddress::Unix(path.clone()),
        };
        let deduped = collect_multi_list(
            vec![Server {
                name: "saved-local".to_owned(),
                address: shared_addr,
            }],
            async { Some(shared_copy) },
            Instant::now() + DISCOVERY_TIME,
        )
        .await;

        assert_eq!(deduped.reachable, 1);
        assert!(deduped.errors.is_empty());
        assert_eq!(deduped.groups.len(), 1);
        assert_eq!(deduped.groups[0].0, "saved-local");
    }
}
