mod app;
mod rex;
mod session;

use std::collections::{HashMap, HashSet};
use std::env;

use anyhow::Result;
use serde_json::{Value, json};

use crate::rex::ServerAddress;
use crate::rex::control::Control;

const USAGE: &str = "\
zrex: use a session on a Rex server from a terminal

Usage:
  zrex [--server ADDRESS] ls
  zrex [--server ADDRESS] a|attach [SESSION] [--window SELECTOR] [--block SELECTOR]
  zrex [--server ADDRESS] kill SESSION
  zrex [--server ADDRESS] completion zsh|bash|fish
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
session already has, and never changes it, leaving what Rex.app shows alone. ls
lists every session, its windows, and any splits (1.1, 1.2, ...) with a star on
the active window and block, and the terminal title a window's focused block
reports beside the window's label. completion prints a shell completion script
that completes session labels, window numbers and labels, and block numbers and
labels from the live server.

While attached:
  Ctrl-backslash          detach, and leave the session running

Terminal output streams directly to your terminal, so your terminal's own
scrollback, mouse selection, and clipboard work as they always do.";

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Help,
    Version,
    List,
    Attach {
        target: Option<String>,
        window: Option<String>,
        block: Option<String>,
    },
    Kill {
        target: String,
    },
    Completion(String),
    Unknown(String),
}

fn parse_args<I>(args: I, env_server: Option<String>) -> Result<(Option<String>, Command)>
where
    I: IntoIterator<Item = String>,
{
    let mut server = env_server.filter(|address| !address.is_empty());
    let mut command: Option<String> = None;
    let mut target: Option<String> = None;
    let mut window: Option<String> = None;
    let mut block: Option<String> = None;

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok((server, Command::Help)),
            "-V" | "--version" => return Ok((server, Command::Version)),
            "-S" | "--server" => match args.next() {
                Some(value) => server = Some(value),
                None => anyhow::bail!("--server needs an address"),
            },
            "-w" | "--window" => match args.next() {
                Some(value) => window = Some(value),
                None => anyhow::bail!("--window needs a window number, a label, or -"),
            },
            "-b" | "--block" => match args.next() {
                Some(value) => block = Some(value),
                None => anyhow::bail!("--block needs a block number, a label, or an ID"),
            },
            other if command.is_none() => command = Some(other.to_owned()),
            other if target.is_none() => target = Some(other.to_owned()),
            other => anyhow::bail!("unexpected argument {other}"),
        }
    }

    let cmd = match command.as_deref() {
        Some("ls") => Command::List,
        Some("a" | "attach") => Command::Attach {
            target,
            window,
            block,
        },
        Some("kill") => match target {
            Some(target) => Command::Kill { target },
            None => anyhow::bail!("kill needs a session"),
        },
        Some("completion") => match target.as_deref() {
            Some(shell @ ("zsh" | "bash" | "fish")) => Command::Completion(shell.to_owned()),
            Some(other) => {
                anyhow::bail!("no completion script for {other}; use zsh, bash, or fish")
            }
            None => anyhow::bail!("completion needs zsh, bash, or fish"),
        },
        Some(other) => Command::Unknown(other.to_owned()),
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
        complete(args.collect()).await;
        return Ok(());
    }
    let (configured_server, command) =
        parse_args(first.into_iter().chain(args), env::var("REX_SERVER").ok())?;
    let server_address = || match configured_server.as_deref() {
        Some(address) => address.parse(),
        None => Ok(ServerAddress::local_or_loopback()),
    };

    match command {
        Command::Help => {
            println!("{USAGE}");
            Ok(())
        }
        Command::Version => {
            println!("zrex {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::List => list(&server_address()?).await,
        Command::Attach {
            target,
            window,
            block,
        } => app::attach(&server_address()?, target, window, block).await,
        Command::Kill { target } => kill(&server_address()?, &target).await,
        Command::Completion(shell) => {
            print!("{}", completion_script(&shell));
            Ok(())
        }
        Command::Unknown(other) => {
            eprintln!("unknown command {other}\n\n{USAGE}");
            std::process::exit(2);
        }
    }
}

async fn list(server: &ServerAddress) -> Result<()> {
    let (mut ctrl, _events) = Control::connect(server, None).await?;
    let sessions = session::list_all(&mut ctrl).await?;
    if sessions.is_empty() {
        println!("no sessions");
        return Ok(());
    }
    let width = sessions
        .iter()
        .map(|session| session::label_of(session).chars().count())
        .max()
        .unwrap_or(0);
    for entry in sessions {
        let id = session::id_of(&entry);
        let view = session::view(&mut ctrl, &id).await.ok();
        let titles = match &view {
            Some(view) => window_titles(&mut ctrl, &id, view).await,
            None => HashMap::new(),
        };
        for line in format_session(&entry, view.as_ref(), width, &titles) {
            println!("{line}");
        }
    }
    Ok(())
}

/// The tab title Rex.app shows comes from the terminal, not the window label.
async fn window_titles(
    ctrl: &mut Control,
    session_id: &str,
    view: &Value,
) -> HashMap<String, String> {
    let mut pending = Vec::new();
    for window in session::windows(view) {
        let Some(block_id) = window.active_block_id else {
            continue;
        };
        let payload = json!({"session_id": session_id, "block_id": block_id});
        if let Ok(reply) = ctrl.start_call("com.superlogical.terminal.title", payload) {
            pending.push((window.id, reply));
        }
    }
    let mut titles = HashMap::new();
    for (window_id, reply) in pending {
        if let Ok(Ok(reply)) = reply.await
            && let Some(title) = reply.get("title").and_then(Value::as_str)
            && !title.is_empty()
        {
            titles.insert(window_id, title.to_owned());
        }
    }
    titles
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

/// Terminal titles come from programs, so strip control characters and keep a
/// listing to one line before printing one.
fn clean_title(title: &str) -> String {
    let cleaned: String = title
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    let cleaned = cleaned.trim();
    let mut short: String = cleaned.chars().take(80).collect();
    if cleaned.chars().count() > 80 {
        short.pop();
        short.push('…');
    }
    short
}

const COMPLETION_COMMANDS: [&str; 5] = ["a", "attach", "kill", "ls", "completion"];

#[derive(Debug, PartialEq, Eq)]
enum Completion {
    Commands,
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

/// Reads the words before the cursor the way `parse_args` does, but never fails.
fn completion_context(words: &[String]) -> Completion {
    let Some((current, done)) = words.split_last() else {
        return Completion::Commands;
    };
    let mut command: Option<String> = None;
    let mut target: Option<String> = None;
    let mut window: Option<String> = None;
    let mut index = 0;
    while index < done.len() {
        match done[index].as_str() {
            "" => index += 1,
            "-S" | "--server" | "-b" | "--block" => index += 2,
            "-w" | "--window" => {
                window = done.get(index + 1).cloned();
                index += 2;
            }
            word if word.starts_with('-') => index += 1,
            word if command.is_none() => {
                command = Some(word.to_owned());
                index += 1;
            }
            word if target.is_none() => {
                target = Some(word.to_owned());
                index += 1;
            }
            _ => index += 1,
        }
    }
    match done.last().map(String::as_str) {
        Some("-S" | "--server") => return Completion::Nothing,
        Some("-w" | "--window") => return Completion::Windows { session: target },
        Some("-b" | "--block") => {
            return Completion::Blocks {
                session: target,
                window,
            };
        }
        _ => {}
    }
    let attach = matches!(command.as_deref(), Some("a" | "attach"));
    if current.starts_with('-') && current != "-" {
        return Completion::Flags { attach };
    }
    match command.as_deref() {
        None => Completion::Commands,
        Some("a" | "attach" | "kill") if target.is_none() => Completion::Sessions,
        Some("a" | "attach") => Completion::Flags { attach: true },
        Some("kill" | "ls" | "completion") => Completion::Flags { attach: false },
        Some(_) => Completion::Nothing,
    }
}

async fn complete(words: Vec<String>) {
    let current = words.last().cloned().unwrap_or_default();
    let context = completion_context(&words);
    if context == Completion::Nothing {
        return;
    }
    let Some(server) = completion_server(&words) else {
        return;
    };
    let candidates = match context {
        Completion::Nothing => return,
        Completion::Commands => COMPLETION_COMMANDS.into_iter().map(str::to_owned).collect(),
        Completion::Flags { attach } => flags(attach),
        Completion::Sessions => session_candidates(&server).await,
        Completion::Windows { session } => window_candidates(&server, session.as_deref()).await,
        Completion::Blocks { session, window } => {
            block_candidates(&server, session.as_deref(), window.as_deref()).await
        }
    };
    let prefix = current.to_lowercase();
    for candidate in candidates {
        if candidate.to_lowercase().starts_with(&prefix) {
            println!("{candidate}");
        }
    }
}

/// A completion runs in a fresh process, so it resolves the server the same way
/// the command it completes will.
fn completion_server(words: &[String]) -> Option<ServerAddress> {
    let mut index = 0;
    while index < words.len() {
        if matches!(words[index].as_str(), "-S" | "--server") {
            return words.get(index + 1)?.parse().ok();
        }
        index += 1;
    }
    match env::var("REX_SERVER")
        .ok()
        .filter(|address| !address.is_empty())
    {
        Some(address) => address.parse().ok(),
        None => Some(ServerAddress::local_or_loopback()),
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
    let session = match target {
        Some(target) => sessions
            .iter()
            .find(|session| session::matches(session, target))?,
        None => sessions.first()?,
    };
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
    let windows = session::windows(&view);
    let window = match window_selector {
        Some(selector) => {
            let window_id = session::find_window(&view, selector).or_else(|| {
                selector
                    .split_once('.')
                    .and_then(|(window, _block)| session::find_window(&view, window))
            });
            window_id.and_then(|id| windows.into_iter().find(|window| window.id == id))
        }
        None => {
            let active = session::active_window_id(&view);
            windows
                .into_iter()
                .find(|window| Some(window.id.as_str()) == active)
        }
    };
    let Some(window) = window else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    for (number, block) in window.blocks.into_iter().enumerate() {
        candidates.push((number + 1).to_string());
        if !block.label.is_empty() {
            candidates.push(block.label);
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

fn completion_script(shell: &str) -> &'static str {
    match shell {
        "zsh" => include_str!("../completions/zrex.zsh"),
        "bash" => include_str!("../completions/zrex.bash"),
        _ => include_str!("../completions/zrex.fish"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parses_cli_flags_and_commands() {
        let (server, cmd) = parse_args(args(&["ls"]), None).unwrap();
        assert_eq!(server, None);
        assert_eq!(cmd, Command::List);
        assert_eq!(
            parse_args(args(&["ls"]), Some(String::new())).unwrap().0,
            None
        );

        let (server, cmd) = parse_args(
            args(&["-S", "https://example.com", "a", "work", "-w", "1.2"]),
            Some("http://env:7297".to_owned()),
        )
        .unwrap();
        assert_eq!(server.as_deref(), Some("https://example.com"));
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
        assert_eq!(server.as_deref(), Some("http://env:7297"));
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
            Command::Completion("zsh".to_owned())
        );
        assert!(parse_args(args(&["completion", "powershell"]), None).is_err());
        assert!(parse_args(args(&["completion"]), None).is_err());
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
        let lines = format_session(&entry, Some(&view), 4, &HashMap::new());
        assert_eq!(
            lines,
            vec![
                "work  session:1",
                "  * 1  Window one",
                "      1.1  Block one",
                "    * 1.2  Block two",
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
        assert_eq!(completion_context(&args(&[""])), Completion::Commands);
        assert_eq!(completion_context(&args(&["a", ""])), Completion::Sessions);
        assert_eq!(
            completion_context(&args(&["kill", ""])),
            Completion::Sessions
        );
        assert_eq!(
            completion_context(&args(&["a", "work", "-w", ""])),
            Completion::Windows {
                session: Some("work".to_owned())
            }
        );
        assert_eq!(
            completion_context(&args(&["a", "work", "-w", "1", "-b", ""])),
            Completion::Blocks {
                session: Some("work".to_owned()),
                window: Some("1".to_owned())
            }
        );
        assert_eq!(
            completion_context(&args(&["a", "work", "--w"])),
            Completion::Flags { attach: true }
        );
        assert_eq!(
            completion_context(&args(&["-S", "http://example.com", ""])),
            Completion::Commands
        );
        assert_eq!(completion_context(&args(&["-S", ""])), Completion::Nothing);
    }
}
