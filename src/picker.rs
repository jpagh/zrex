mod prompt;

use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use futures_util::{StreamExt, future::join_all, stream::FuturesUnordered};
use serde_json::{Value, json};
use tokio::time::{Instant, timeout_at};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::app;
use crate::config::{self, DISCOVERY_TIME, Server};
use crate::rex::{ServerAddress, ServerConfig, control::Control};
use crate::session::{self, PendingCall};
use crate::{clean_one_line, clean_truncated};

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProgramStatus {
    state: ProgramState,
    summary: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StyleRole {
    Server,
    Label,
    Separator,
    Title,
    Status(ProgramState),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct StyledSpan {
    pub(super) role: StyleRole,
    pub(super) text: String,
    /// Starting char index in `Target::search_text()`, or `None` for a synthetic ellipsis.
    pub(super) search_offset: Option<usize>,
}

pub(super) struct Target {
    label: String,
    label_parts: TargetLabel,
    title: String,
    status: Option<ProgramStatus>,
    session_id: String,
    block_id: String,
}

struct TargetLabel {
    prefix: String,
    window: Option<String>,
    block: Option<String>,
    fallback: String,
}

impl TargetLabel {
    fn format(&self, process: Option<&str>) -> String {
        let mut detail = Vec::new();
        if let Some(window) = &self.window {
            detail.push(window.as_str());
        }
        if let Some(block) = &self.block
            && !detail.iter().any(|part| part.eq_ignore_ascii_case(block))
        {
            detail.push(block.as_str());
        }
        if let Some(process) = process
            && !detail.iter().any(|part| part.eq_ignore_ascii_case(process))
        {
            detail.push(process);
        }
        if detail.is_empty() && !self.fallback.is_empty() {
            detail.push(self.fallback.as_str());
        }
        if detail.is_empty() {
            self.prefix.clone()
        } else {
            format!("{} {}", self.prefix, detail.join(" / "))
        }
    }
}

struct DiscoveryOutcome {
    servers: Vec<Server>,
    choices: Vec<(usize, Target)>,
    warnings: Vec<String>,
}

pub async fn run(server_config: &ServerConfig) -> Result<()> {
    app::ensure_terminal()?;
    let (servers, discover_local) = load_servers(server_config)?;
    let deadline = Instant::now() + DISCOVERY_TIME;
    let outcome = discover_all(
        servers,
        discover_local.then(ServerAddress::local_if_running),
        deadline,
    )
    .await;
    for warning in outcome.warnings {
        eprintln!("zrex pick: {warning}");
    }
    if outcome.choices.is_empty() {
        bail!("no attachable sessions found");
    }

    let targets: Vec<_> = outcome.choices.iter().map(|(_, target)| target).collect();
    if let Some(index) = prompt::select(&targets)? {
        let (server_index, target) = &outcome.choices[index];
        let server = &outcome.servers[*server_index];
        app::attach_existing(&server.address, &target.session_id, &target.block_id).await?;
    }
    Ok(())
}

async fn discover_all<F>(
    servers: Vec<Server>,
    local_probe: Option<F>,
    deadline: Instant,
) -> DiscoveryOutcome
where
    F: Future<Output = Option<ServerAddress>>,
{
    // Resolve and query the default local server in parallel with saved servers
    // so a hung local socket never delays remote discovery.
    let local_future = async {
        let Some(probe) = local_probe else {
            return Ok(None);
        };
        let Some(address) = timeout_at(deadline, probe)
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
    let mut warnings = Vec::new();
    match local_outcome {
        Ok(Some((server, result))) => {
            all_servers.push(server);
            all_results.push(result);
        }
        Ok(None) => {}
        Err(error) => warnings.push(clean_one_line(&format!("{error:#}"))),
    }
    all_servers.extend(servers);
    all_results.extend(discovered);

    let mut choices = Vec::new();
    for (server_index, (server, result)) in all_servers.iter().zip(all_results).enumerate() {
        match result {
            Ok((targets, missing_views)) => {
                if missing_views > 0 {
                    warnings.push(format!(
                        "{}: could not list windows for {missing_views} session(s)",
                        clean_one_line(&server.name)
                    ));
                }
                choices.extend(targets.into_iter().map(|target| (server_index, target)));
            }
            Err(error) => warnings.push(format!(
                "{}: {}",
                clean_one_line(&server.name),
                clean_one_line(&format!("{error:#}"))
            )),
        }
    }

    DiscoveryOutcome {
        servers: all_servers,
        choices,
        warnings,
    }
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

    let mut servers = config::load_saved_servers("pick")?.servers;
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
                Err(error) => eprintln!("zrex pick: {}", clean_one_line(&format!("{error:#}"))),
            }
            Ok((servers, false))
        }
        ServerConfig::Default => Ok((servers, true)),
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

async fn optional_reply(deadline: Instant, call: Result<PendingCall>) -> Option<Value> {
    timeout_at(deadline, call.ok()?).await.ok()?.ok()?.ok()
}

fn describe_targets(
    ctrl: &mut Control,
    deadline: Instant,
    index: usize,
    mut targets: Vec<Target>,
) -> impl Future<Output = (usize, Vec<Target>)> + use<> {
    let mut requests = HashMap::new();
    for target in &targets {
        // Deduplicate metadata queries per block ID.
        requests.entry(target.block_id.clone()).or_insert_with(|| {
            let title = session::start_terminal_title(ctrl, &target.session_id, &target.block_id);
            let status = ctrl.start_call(
                "com.superlogical.terminal.program_status",
                json!({"session_id": target.session_id, "block_id": target.block_id}),
            );
            let process =
                session::start_terminal_process(ctrl, &target.session_id, &target.block_id);
            (title, status, process)
        });
    }
    async move {
        let details: HashMap<_, _> = join_all(requests.into_iter().map(
            |(id, (title, status, process))| async move {
                let (title, status, process) = tokio::join!(
                    optional_reply(deadline, title),
                    optional_reply(deadline, status),
                    optional_reply(deadline, process)
                );
                let title = title
                    .as_ref()
                    .and_then(|reply| session::live_terminal_title(reply, process.as_ref()))
                    .map_or_else(String::new, |title| clean_truncated(title, 64));
                let status = status.as_ref().and_then(status_summary);
                let process = process.as_ref().and_then(process_name);
                (id, (title, status, process))
            },
        ))
        .await
        .into_iter()
        .collect();
        for target in &mut targets {
            if let Some((title, status, process)) = details.get(&target.block_id) {
                target.label = target.label_parts.format(process.as_deref());
                target.title.clone_from(title);
                target.status.clone_from(status);
            }
        }
        (index, targets)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum ProgramState {
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

fn status_summary(reply: &Value) -> Option<ProgramStatus> {
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
    Some(ProgramStatus { state, summary })
}

fn clean_json_field(value: &Value, key: &str, max_chars: usize) -> String {
    clean_truncated(
        value.get(key).and_then(Value::as_str).unwrap_or_default(),
        max_chars,
    )
}

fn process_name(reply: &Value) -> Option<String> {
    reply
        .get("foreground")
        .and_then(label_for_process)
        .or_else(|| reply.get("child").and_then(label_for_process))
}

/// Follows Rex's `com.superlogical.terminal.process` guidance: prefer `script`,
/// then `argv0`, then `name`, reduced to a short display name.
fn label_for_process(process: &Value) -> Option<String> {
    if process.is_null() {
        return None;
    }
    for (key, strip_login_dash) in [("script", false), ("argv0", true), ("name", false)] {
        let Some(raw) = process.get(key).and_then(Value::as_str) else {
            continue;
        };
        let cleaned = clean_one_line(raw);
        let candidate = if strip_login_dash {
            cleaned.strip_prefix('-').unwrap_or(&cleaned)
        } else {
            &cleaned
        };
        let base = basename(candidate);
        let base = if strip_login_dash {
            base.strip_prefix('-').unwrap_or(base)
        } else {
            base
        };
        let short = clean_truncated(base, 24);
        if !short.is_empty() {
            return Some(short);
        }
    }
    None
}

fn basename(value: &str) -> &str {
    let trimmed = value.trim_end_matches(['/', '\\']);
    trimmed.rsplit(['/', '\\']).next().unwrap_or(trimmed)
}

fn custom_window_label(label: &str) -> Option<String> {
    let clean = clean_one_line(label);
    if clean.is_empty() || is_default_window_label(&clean) {
        None
    } else {
        Some(clean)
    }
}

fn is_default_window_label(label: &str) -> bool {
    label
        .strip_prefix("Window ")
        .is_some_and(|hex| hex.len() == 8 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn custom_block_label(label: &str) -> Option<String> {
    let clean = clean_one_line(label);
    if clean.is_empty() || clean.eq_ignore_ascii_case("shell") {
        None
    } else {
        Some(clean)
    }
}

fn targets(server: &str, entry: &Value, session_id: &str, view: &Value) -> Vec<Target> {
    let session = format!(
        "[{}] {}",
        clean_one_line(server),
        label_or_id(session::label_of(entry), session_id)
    );
    let mut targets = Vec::new();
    let mut add = |label_parts: TargetLabel, block_id: &str| {
        let label = label_parts.format(None);
        targets.push(Target {
            label,
            label_parts,
            title: String::new(),
            status: None,
            session_id: session_id.to_owned(),
            block_id: block_id.to_owned(),
        });
    };
    let windows = session::windows(view);
    for (index, window) in windows.iter().enumerate() {
        let number = index + 1;
        let window_label = custom_window_label(&window.label);
        if window.blocks.len() > 1 {
            for (split_index, block) in window.blocks.iter().enumerate() {
                let fallback = label_or_id(&block.label, &block.id);
                add(
                    TargetLabel {
                        prefix: format!("{session} / {number}.{}", split_index + 1),
                        window: window_label.clone(),
                        block: custom_block_label(&block.label),
                        fallback,
                    },
                    &block.id,
                );
            }
        } else if let Some(block_id) = window.active_or_first_block_id() {
            let block_label = window
                .blocks
                .iter()
                .find(|block| block.id == block_id)
                .map(|block| block.label.as_str())
                .unwrap_or_default();
            let fallback = {
                let clean = clean_one_line(block_label);
                if clean.is_empty() {
                    label_or_id(&window.label, &window.id)
                } else {
                    clean
                }
            };
            add(
                TargetLabel {
                    prefix: format!("{session} / {number}"),
                    window: window_label,
                    block: custom_block_label(block_label),
                    fallback,
                },
                block_id,
            );
        }
    }
    targets
}

impl Target {
    pub(super) fn search_text(&self) -> String {
        let mut text = String::new();
        let status = self
            .status
            .as_ref()
            .map_or("", |status| status.summary.as_str());
        for (separator, part) in [
            ("", self.label.as_str()),
            (" — ", self.title.as_str()),
            (" · ", status),
        ] {
            if !part.is_empty() {
                text.push_str(separator);
                text.push_str(part);
            }
        }
        text
    }

    pub(super) fn styled_row(&self, columns: usize) -> Vec<StyledSpan> {
        if columns == 0 {
            return Vec::new();
        }
        struct Part<'a> {
            separator: &'static str,
            sep_offset: usize,
            text: &'a str,
            text_offset: usize,
            role: StyleRole,
            width: usize,
            limit: usize,
        }

        let mut parts = Vec::with_capacity(3);
        let mut char_pos = 0usize;
        let candidates = [
            ("", self.label.as_str(), StyleRole::Label),
            (" — ", self.title.as_str(), StyleRole::Title),
            (
                " · ",
                self.status
                    .as_ref()
                    .map_or("", |status| status.summary.as_str()),
                StyleRole::Status(
                    self.status
                        .as_ref()
                        .map_or(ProgramState::Idle, |status| status.state),
                ),
            ),
        ];
        for (separator, text, role) in candidates {
            if text.is_empty() {
                continue;
            }
            let sep_offset = char_pos;
            char_pos += separator.chars().count();
            let text_offset = char_pos;
            char_pos += text.chars().count();
            parts.push(Part {
                separator,
                sep_offset,
                text,
                text_offset,
                role,
                width: text.width(),
                limit: 0,
            });
        }
        if parts.is_empty() {
            return Vec::new();
        }

        // Drop trailing parts until each kept part can show its separator plus
        // at least one non-ellipsis character (or its full width if shorter).
        while parts.len() > 1 {
            let separators: usize = parts.iter().map(|part| part.separator.width()).sum();
            let min_text: usize = parts.iter().map(|part| part.width.min(2)).sum();
            if columns >= separators + min_text {
                break;
            }
            parts.pop();
        }

        let separators: usize = parts.iter().map(|part| part.separator.width()).sum();
        let budget = columns.saturating_sub(separators);
        let total_width: usize = parts.iter().map(|part| part.width).sum();
        if total_width <= budget {
            for part in &mut parts {
                part.limit = part.width;
            }
        } else {
            // Share display columns evenly across the kept parts.
            for _ in 0..budget {
                let Some(part) = parts
                    .iter_mut()
                    .filter(|part| part.limit < part.width)
                    .min_by_key(|part| part.limit)
                else {
                    break;
                };
                part.limit += 1;
            }
        }

        let mut spans = Vec::new();
        for part in parts {
            if part.limit == 0 {
                continue;
            }
            if !part.separator.is_empty() {
                spans.push(StyledSpan {
                    role: StyleRole::Separator,
                    text: part.separator.to_owned(),
                    search_offset: Some(part.sep_offset),
                });
            }
            let (visible, truncated) = if part.width <= part.limit {
                (part.text.to_owned(), false)
            } else {
                let ellipsis_width = '…'.width().unwrap_or(1);
                (
                    prefix_to_columns(part.text, part.limit.saturating_sub(ellipsis_width)),
                    true,
                )
            };
            if part.role == StyleRole::Label {
                push_label_spans(&mut spans, &visible, part.text_offset, truncated);
            } else {
                if !visible.is_empty() {
                    spans.push(StyledSpan {
                        role: part.role,
                        text: visible,
                        search_offset: Some(part.text_offset),
                    });
                }
                if truncated {
                    spans.push(StyledSpan {
                        role: part.role,
                        text: "…".to_owned(),
                        search_offset: None,
                    });
                }
            }
        }
        spans
    }

    #[cfg(test)]
    fn row(&self, columns: usize) -> String {
        self.styled_row(columns)
            .into_iter()
            .map(|span| span.text)
            .collect()
    }
}

fn push_label_spans(
    spans: &mut Vec<StyledSpan>,
    visible: &str,
    mut offset: usize,
    truncated: bool,
) {
    let mut rest = visible;
    if rest.starts_with('[') {
        if let Some(end) = rest.find(']') {
            let server = &rest[..=end];
            spans.push(StyledSpan {
                role: StyleRole::Server,
                text: server.to_owned(),
                search_offset: Some(offset),
            });
            offset += server.chars().count();
            rest = &rest[end + 1..];
        } else {
            spans.push(StyledSpan {
                role: StyleRole::Server,
                text: rest.to_owned(),
                search_offset: Some(offset),
            });
            if truncated {
                spans.push(StyledSpan {
                    role: StyleRole::Server,
                    text: "…".to_owned(),
                    search_offset: None,
                });
            }
            return;
        }
    }

    let mut first = true;
    for segment in rest.split(" / ") {
        if !first {
            spans.push(StyledSpan {
                role: StyleRole::Separator,
                text: " / ".to_owned(),
                search_offset: Some(offset),
            });
            offset += 3;
        }
        first = false;
        if !segment.is_empty() {
            spans.push(StyledSpan {
                role: StyleRole::Label,
                text: segment.to_owned(),
                search_offset: Some(offset),
            });
            offset += segment.chars().count();
        }
    }
    if truncated {
        spans.push(StyledSpan {
            role: StyleRole::Label,
            text: "…".to_owned(),
            search_offset: None,
        });
    }
}

fn prefix_to_columns(text: &str, max_columns: usize) -> String {
    let mut out = String::new();
    let mut used = 0;
    for ch in text.chars() {
        let ch_width = ch.width().unwrap_or(0);
        if used + ch_width > max_columns {
            break;
        }
        out.push(ch);
        used += ch_width;
    }
    out
}

fn label_or_id(label: &str, id: &str) -> String {
    let label = clean_one_line(label);
    if label.is_empty() {
        clean_one_line(id)
    } else {
        label
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_target(label: &str, title: &str, status: &str) -> Target {
        let status = if status.is_empty() {
            None
        } else {
            Some(ProgramStatus {
                state: ProgramState::from_str(status.split_whitespace().next().unwrap_or_default()),
                summary: status.to_owned(),
            })
        };
        Target {
            label: label.to_owned(),
            label_parts: TargetLabel {
                prefix: label.to_owned(),
                window: None,
                block: None,
                fallback: String::new(),
            },
            title: title.to_owned(),
            status,
            session_id: "session:1".to_owned(),
            block_id: "block:1".to_owned(),
        }
    }

    #[test]
    fn row_truncates_by_display_width_for_multibyte_and_wide_text() {
        let target = sample_target("πππ", "αβγ", "");
        // "πππ — αβγ" is 9 display columns (15 UTF-8 bytes) and must not truncate at 9.
        assert_eq!(target.row(9), "πππ — αβγ");
        assert_eq!(target.search_text(), "πππ — αβγ");

        let pi = sample_target("πππ", "", "");
        assert_eq!(pi.row(5), "πππ");
        assert_eq!(pi.row(2), "π…");
        assert_eq!(pi.row(1), "…");
        assert_eq!(pi.row(0), "");

        // Wide CJK characters (2 columns each) never overflow the column limit.
        let cjk = sample_target("你好世界", "测试标题", "blocked");
        for columns in 0..=20 {
            let rendered = cjk.row(columns);
            assert!(
                rendered.width() <= columns,
                "row {rendered:?} exceeded {columns} columns (width {})",
                rendered.width()
            );
        }
        assert_eq!(sample_target("你好世界", "", "").row(4), "你…");
    }

    #[test]
    fn row_drops_trailing_parts_when_narrow_so_label_remains_visible() {
        let target = sample_target("[local] work", "vim README.md", "working claude");
        let rendered = target.row(5);
        assert_eq!(rendered, "[loc…");
        assert!(rendered.width() <= 5);
    }

    #[test]
    fn styled_row_assigns_semantic_roles_and_aligned_search_offsets() {
        let target = sample_target(
            "[office] work / 1 dev",
            "vim README.md",
            "blocked claude-code",
        );
        let search: Vec<char> = target.search_text().chars().collect();
        let spans = target.styled_row(100);
        assert_eq!(
            spans
                .iter()
                .map(|span| (span.role, span.text.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (StyleRole::Server, "[office]"),
                (StyleRole::Label, " work"),
                (StyleRole::Separator, " / "),
                (StyleRole::Label, "1 dev"),
                (StyleRole::Separator, " — "),
                (StyleRole::Title, "vim README.md"),
                (StyleRole::Separator, " · "),
                (
                    StyleRole::Status(ProgramState::Blocked),
                    "blocked claude-code"
                ),
            ]
        );
        for span in &spans {
            if let Some(offset) = span.search_offset {
                let actual: String = search[offset..offset + span.text.chars().count()]
                    .iter()
                    .collect();
                assert_eq!(actual, span.text);
            }
        }

        // Truncated spans keep valid offsets for prefix chars and None for synthetic ellipses.
        let truncated = target.styled_row(28);
        assert!(truncated.iter().any(|span| span.search_offset.is_none()));
        for span in &truncated {
            if let Some(offset) = span.search_offset {
                let actual: String = search[offset..offset + span.text.chars().count()]
                    .iter()
                    .collect();
                assert_eq!(actual, span.text);
            } else {
                assert_eq!(span.text, "…");
            }
        }
    }

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
            status_summary(&reply),
            Some(ProgramStatus {
                state: ProgramState::Blocked,
                summary: "blocked claude-code (permission) 80%: shell: allow run?".to_owned(),
            })
        );

        let fallback = json!({
            "records": [
                {"state": "done", "app": "pytest", "progress": 100, "kind": "permission", "msg": "ok"}
            ]
        });
        // Progress and kind are omitted for non-working/non-blocked states.
        assert_eq!(
            status_summary(&fallback),
            Some(ProgramStatus {
                state: ProgramState::Done,
                summary: "done pytest: ok".to_owned(),
            })
        );

        assert_eq!(status_summary(&json!({"records": []})), None);
    }

    #[test]
    fn process_name_prefers_script_then_argv0_then_name() {
        assert_eq!(
            process_name(&json!({
                "foreground": {
                    "script": "/opt/homebrew/bin/agy",
                    "argv0": "node",
                    "name": "node"
                }
            }))
            .as_deref(),
            Some("agy")
        );
        assert_eq!(
            process_name(&json!({
                "foreground": {
                    "argv0": "-zsh",
                    "name": "zsh"
                }
            }))
            .as_deref(),
            Some("zsh")
        );
        assert_eq!(
            process_name(&json!({
                "foreground": {
                    "argv0": "/bin/zsh",
                    "name": "zsh"
                }
            }))
            .as_deref(),
            Some("zsh")
        );
        assert_eq!(
            process_name(&json!({
                "foreground": null,
                "child": {
                    "argv0": "",
                    "name": "fish"
                }
            }))
            .as_deref(),
            Some("fish")
        );
        assert_eq!(
            process_name(&json!({"foreground": null, "child": null})),
            None
        );
    }

    #[test]
    fn targets_hide_default_window_and_shell_labels_and_show_process() {
        let entry = json!({"session_id": "session:1", "label": "zrex"});
        let view = json!({
            "active_window_id": "window:1",
            "windows": [
                {
                    "window_id": "window:1",
                    "label": "Window 3926b0bc",
                    "focused_block_id": "block:1",
                    "layers": [{
                        "blocks": [
                            {"block_id": "block:1", "label": "shell"}
                        ]
                    }]
                },
                {
                    "window_id": "window:2",
                    "label": "Window 1133dbdb",
                    "focused_block_id": "block:3",
                    "layers": [{
                        "blocks": [
                            {"block_id": "block:2", "label": "shell"},
                            {"block_id": "block:3", "label": "shell"}
                        ]
                    }]
                },
                {
                    "window_id": "window:3",
                    "label": "dev",
                    "focused_block_id": "block:4",
                    "layers": [{
                        "blocks": [
                            {"block_id": "block:4", "label": "editor"},
                            {"block_id": "block:5", "label": "shell"}
                        ]
                    }]
                }
            ]
        });
        let list = targets("local", &entry, "session:1", &view);
        assert_eq!(
            list.iter()
                .map(|t| (t.label.as_str(), t.block_id.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("[local] zrex / 1 shell", "block:1"),
                ("[local] zrex / 2.1 shell", "block:2"),
                ("[local] zrex / 2.2 shell", "block:3"),
                ("[local] zrex / 3.1 dev / editor", "block:4"),
                ("[local] zrex / 3.2 dev", "block:5"),
            ]
        );

        let with_processes: Vec<_> = list
            .iter()
            .zip(["agy", "zsh", "zsh", "nvim", "zsh"])
            .map(|(target, proc)| target.label_parts.format(Some(proc)))
            .collect();
        assert_eq!(
            with_processes,
            vec![
                "[local] zrex / 1 agy",
                "[local] zrex / 2.1 zsh",
                "[local] zrex / 2.2 zsh",
                "[local] zrex / 3.1 dev / editor / nvim",
                "[local] zrex / 3.2 dev / zsh",
            ]
        );
    }

    #[tokio::test]
    async fn discover_all_skips_absent_local_silently_and_reports_saved_server_errors() {
        use futures_util::SinkExt;
        use tokio::net::TcpListener;
        use tokio_tungstenite::accept_hdr_async;
        use tokio_tungstenite::tungstenite::Message;
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_addr = listener.local_addr().unwrap();
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
                    "session.attach_all" => json!({
                        "sessions": [{"session_id": "session:1", "label": "work"}]
                    }),
                    "session.view" => json!({
                        "active_window_id": "window:1",
                        "windows": [{
                            "window_id": "window:1",
                            "label": "dev",
                            "focused_block_id": "block:1",
                            "layers": [{"blocks": [{"block_id": "block:1", "label": "shell"}]}]
                        }]
                    }),
                    "com.superlogical.terminal.title" => json!({"title": ""}),
                    "com.superlogical.terminal.program_status" => json!({"records": []}),
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

        // Reserve and immediately release a port so connecting to it fails fast.
        let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead_listener.local_addr().unwrap();
        drop(dead_listener);

        let servers = vec![
            Server {
                name: "dead".to_owned(),
                address: format!("http://{dead_addr}").parse().unwrap(),
            },
            Server {
                name: "office".to_owned(),
                address: format!("http://{live_addr}").parse().unwrap(),
            },
        ];

        let outcome = discover_all(
            servers,
            Some(async { None }),
            Instant::now() + DISCOVERY_TIME,
        )
        .await;

        assert_eq!(outcome.choices.len(), 1);
        assert_eq!(outcome.choices[0].1.label, "[office] work / 1 dev");
        assert_eq!(outcome.warnings.len(), 1);
        assert!(outcome.warnings[0].starts_with("dead: "));
    }
}
