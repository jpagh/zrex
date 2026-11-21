mod prompt;

use std::collections::HashMap;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::{StreamExt, future::join_all, stream::FuturesUnordered};
use serde_json::{Value, json};
use tokio::time::{Duration, Instant, timeout_at};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::app;
use crate::config::{self, DISCOVERY_TIME, Server, ServerConfig};
use crate::rex::{ServerAddress, control::Control, proto::ApiError};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SessionChoice {
    pub(super) server_index: usize,
    pub(super) server_name: String,
    pub(super) session_id: String,
    pub(super) label: String,
}

impl SessionChoice {
    pub(super) fn display_name(&self) -> String {
        format!("[{}] {}", self.server_name, self.label)
    }

    pub(super) fn styled_row(&self, columns: usize) -> Vec<StyledSpan> {
        styled_label(&self.display_name(), columns)
    }
}

pub(super) fn styled_server_row(server_name: &str, columns: usize) -> Vec<StyledSpan> {
    styled_label(&format!("[{server_name}]"), columns)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ManageTarget {
    Session {
        server_index: usize,
        session_id: String,
    },
    Window {
        server_index: usize,
        session_id: String,
        window_id: String,
    },
    Block {
        server_index: usize,
        session_id: String,
        block_id: String,
    },
}

impl ManageTarget {
    pub(super) fn server_index(&self) -> usize {
        match self {
            Self::Session { server_index, .. }
            | Self::Window { server_index, .. }
            | Self::Block { server_index, .. } => *server_index,
        }
    }

    pub(super) fn session_id(&self) -> &str {
        match self {
            Self::Session { session_id, .. }
            | Self::Window { session_id, .. }
            | Self::Block { session_id, .. } => session_id,
        }
    }

    pub(super) fn kind_name(&self) -> &'static str {
        match self {
            Self::Session { .. } => "session",
            Self::Window { .. } => "window",
            Self::Block { .. } => "block",
        }
    }
}

#[derive(Clone)]
pub(super) struct Target {
    pub(super) server_index: usize,
    pub(super) session_index: usize,
    pub(super) window_id: String,
    pub(super) window_number: usize,
    pub(super) window_label: Option<String>,
    pub(super) window_block_count: usize,
    pub(super) block_id: String,
    pub(super) block_number: usize,
    pub(super) block_label: Option<String>,
    pub(super) block_raw_label: String,
    pub(super) process: Option<String>,
    label: String,
    label_parts: TargetLabel,
    title: String,
    status: Option<ProgramStatus>,
    pub(super) session_id: String,
}

#[derive(Clone)]
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

const NO_SERVERS_INTRO: &str = "\
zrex: no Rex server found.

To get started, start a local Rex server, set REX_SERVER (or pass -S SERVER),
or add servers under [servers] in ~/.config/zrex/config.toml.
Run `zrex --help` for usage.";

struct DiscoveryOutcome {
    servers: Vec<Server>,
    sessions: Vec<SessionChoice>,
    choices: Vec<Target>,
    warnings: Vec<String>,
    attempted_any: bool,
}

struct LoadedServers {
    servers: Vec<Server>,
    discover_local: bool,
    has_configured_sources: bool,
}

struct ServerDiscovery {
    sessions: Vec<(String, String)>,
    targets: Vec<Target>,
    missing_views: usize,
}

impl DiscoveryOutcome {
    fn has_no_sources(&self, has_configured_sources: bool) -> bool {
        !has_configured_sources && !self.attempted_any
    }

    fn replace_server(
        &mut self,
        server_index: usize,
        discovery: ServerDiscovery,
    ) -> Option<String> {
        let server_name = clean_one_line(&self.servers[server_index].name);
        let warning = (discovery.missing_views > 0).then(|| {
            format!(
                "{server_name}: could not list windows for {} session(s)",
                discovery.missing_views
            )
        });

        let old_sessions = std::mem::take(&mut self.sessions);
        let old_choices = std::mem::take(&mut self.choices);
        let mut new_sessions = Vec::with_capacity(old_sessions.len() + discovery.sessions.len());
        let mut new_choices = Vec::with_capacity(old_choices.len() + discovery.targets.len());

        let mut old_session_map: Vec<Option<usize>> = vec![None; old_sessions.len()];
        let mut replacement_session_offset = None;
        for (old_idx, session) in old_sessions.into_iter().enumerate() {
            if session.server_index == server_index {
                continue;
            }
            if replacement_session_offset.is_none() && session.server_index > server_index {
                replacement_session_offset = Some(new_sessions.len());
                for (session_id, label) in &discovery.sessions {
                    new_sessions.push(SessionChoice {
                        server_index,
                        server_name: server_name.clone(),
                        session_id: session_id.clone(),
                        label: label.clone(),
                    });
                }
            }
            old_session_map[old_idx] = Some(new_sessions.len());
            new_sessions.push(session);
        }
        let replacement_session_offset = replacement_session_offset.unwrap_or_else(|| {
            let offset = new_sessions.len();
            for (session_id, label) in discovery.sessions {
                new_sessions.push(SessionChoice {
                    server_index,
                    server_name: server_name.clone(),
                    session_id,
                    label,
                });
            }
            offset
        });

        let mut inserted_targets = false;
        let mut replacement_targets = discovery.targets;
        for mut target in old_choices {
            if target.server_index == server_index {
                continue;
            }
            if !inserted_targets && target.server_index > server_index {
                for mut replacement in std::mem::take(&mut replacement_targets) {
                    replacement.server_index = server_index;
                    replacement.session_index += replacement_session_offset;
                    new_choices.push(replacement);
                }
                inserted_targets = true;
            }
            if let Some(mapped) = old_session_map.get(target.session_index).copied().flatten() {
                target.session_index = mapped;
                new_choices.push(target);
            }
        }
        if !inserted_targets {
            for mut replacement in replacement_targets {
                replacement.server_index = server_index;
                replacement.session_index += replacement_session_offset;
                new_choices.push(replacement);
            }
        }

        self.sessions = new_sessions;
        self.choices = new_choices;
        warning
    }
}

pub async fn run(server_config: &ServerConfig) -> Result<()> {
    app::ensure_terminal()?;
    let loaded = load_servers(server_config).await?;
    let deadline = Instant::now() + DISCOVERY_TIME;
    let mut outcome = discover_all(
        loaded.servers,
        loaded.discover_local.then(ServerAddress::local_if_running),
        deadline,
    )
    .await;
    for warning in outcome.warnings.drain(..) {
        eprintln!("zrex pick: {warning}");
    }
    if outcome.servers.is_empty() {
        if outcome.has_no_sources(loaded.has_configured_sources) {
            println!("{NO_SERVERS_INTRO}");
            return Ok(());
        }
        bail!("no reachable servers");
    }

    let server_names: Vec<String> = outcome
        .servers
        .iter()
        .map(|server| clean_one_line(&server.name))
        .collect();

    let mut screen = prompt::Screen::enter()?;
    let mut state = prompt::PickerState::new(
        outcome.choices.clone(),
        outcome.sessions.clone(),
        server_names,
    );

    loop {
        match screen.step(&mut state)? {
            None => return Ok(()),
            Some(prompt::Selection::Attach(index)) => {
                let target = outcome.choices[index].clone();
                let server = &outcome.servers[target.server_index];
                drop(screen);
                return app::attach_existing(&server.address, &target.session_id, &target.block_id)
                    .await;
            }
            Some(prompt::Selection::NewSession {
                server_index,
                label,
            }) => {
                let server = &outcome.servers[server_index];
                drop(screen);
                return app::attach_new_session(&server.address, label.as_deref()).await;
            }
            Some(prompt::Selection::NewWindow {
                session_index,
                label,
            }) => {
                let session = outcome.sessions[session_index].clone();
                let server = &outcome.servers[session.server_index];
                drop(screen);
                return app::attach_new_window(
                    &server.address,
                    &session.session_id,
                    label.as_deref(),
                )
                .await;
            }
            Some(prompt::Selection::Rename { target, label }) => {
                let kind = target.kind_name();
                screen.render_busy(&mut state, &format!("Renaming {kind}…"))?;
                let server_index = target.server_index();
                let applied = apply_manage(
                    &outcome.servers[server_index],
                    ManageOp::Rename {
                        target: &target,
                        label: &label,
                    },
                    Instant::now() + DISCOVERY_TIME,
                    DISCOVERY_TIME,
                )
                .await;
                let ok_msg = if label.is_empty() {
                    format!("Reset {kind} name to default")
                } else {
                    format!("Renamed {kind} to {}", clean_one_line(&label))
                };
                let feedback = finish_manage(
                    &mut outcome,
                    server_index,
                    applied,
                    ok_msg,
                    &format!("Rename {kind} failed"),
                );
                state.refresh(outcome.choices.clone(), outcome.sessions.clone(), feedback);
            }
            Some(prompt::Selection::Kill { target }) => {
                let kind = target.kind_name();
                let verb = if matches!(target, ManageTarget::Session { .. }) {
                    "Destroying"
                } else {
                    "Closing"
                };
                screen.render_busy(&mut state, &format!("{verb} {kind}…"))?;
                let server_index = target.server_index();
                let applied = apply_manage(
                    &outcome.servers[server_index],
                    ManageOp::Kill { target: &target },
                    Instant::now() + DISCOVERY_TIME,
                    DISCOVERY_TIME,
                )
                .await;
                let ok_msg = if matches!(target, ManageTarget::Session { .. }) {
                    "Destroyed session".to_owned()
                } else {
                    format!("Closed {kind}")
                };
                let feedback = finish_manage(
                    &mut outcome,
                    server_index,
                    applied,
                    ok_msg,
                    &format!("Kill {kind} failed"),
                );
                state.refresh(outcome.choices.clone(), outcome.sessions.clone(), feedback);
            }
        }
    }
}

enum ManageOp<'a> {
    Rename {
        target: &'a ManageTarget,
        label: &'a str,
    },
    Kill {
        target: &'a ManageTarget,
    },
}

struct ManageOutcome {
    result: Result<()>,
    refreshed: Option<Result<ServerDiscovery>>,
}

async fn apply_manage(
    server: &Server,
    op: ManageOp<'_>,
    op_deadline: Instant,
    refresh_timeout: Duration,
) -> ManageOutcome {
    let mut ctrl = match timeout_at(op_deadline, Control::connect(&server.address, None)).await {
        Ok(Ok((ctrl, _events))) => ctrl,
        Ok(Err(error)) => {
            return ManageOutcome {
                result: Err(error),
                refreshed: None,
            };
        }
        Err(_) => {
            return ManageOutcome {
                result: Err(anyhow!("operation timed out")),
                refreshed: None,
            };
        }
    };

    let result = timeout_at(op_deadline, async {
        match op {
            ManageOp::Rename { target, label } => {
                ctrl.call("session.attach", json!({"session_id": target.session_id()}))
                    .await?;
                match target {
                    ManageTarget::Session { session_id, .. } => {
                        session::set_label(&mut ctrl, session_id, label).await
                    }
                    ManageTarget::Window {
                        session_id,
                        window_id,
                        ..
                    } => session::set_window_label(&mut ctrl, session_id, window_id, label).await,
                    ManageTarget::Block {
                        session_id,
                        block_id,
                        ..
                    } => session::set_block_label(&mut ctrl, session_id, block_id, label).await,
                }
            }
            ManageOp::Kill { target } => match target {
                ManageTarget::Session { session_id, .. } => {
                    session::destroy(&mut ctrl, session_id).await
                }
                ManageTarget::Window {
                    session_id,
                    window_id,
                    ..
                } => {
                    ctrl.call("session.attach", json!({"session_id": session_id}))
                        .await?;
                    session::close_window(&mut ctrl, session_id, window_id).await
                }
                ManageTarget::Block {
                    session_id,
                    block_id,
                    ..
                } => {
                    ctrl.call("session.attach", json!({"session_id": session_id}))
                        .await?;
                    session::close_block(&mut ctrl, session_id, block_id).await
                }
            },
        }
    })
    .await
    .map_err(|_| anyhow!("operation timed out"))
    .and_then(|inner| inner);

    let should_refresh = match &result {
        Ok(()) => true,
        Err(error) => error.downcast_ref::<ApiError>().is_some_and(|api| {
            matches!(
                api.code.as_str(),
                "not_found" | "session_not_found" | "conflict"
            )
        }),
    };
    let refreshed = if should_refresh {
        Some(discover_with_control(&mut ctrl, server, Instant::now() + refresh_timeout).await)
    } else {
        None
    };

    ManageOutcome { result, refreshed }
}

fn finish_manage(
    outcome: &mut DiscoveryOutcome,
    server_index: usize,
    applied: ManageOutcome,
    ok_message: String,
    err_prefix: &str,
) -> prompt::Feedback {
    let mut refresh_note = None;
    if let Some(refreshed) = applied.refreshed {
        match refreshed {
            Ok(discovery) => {
                if let Some(warning) = outcome.replace_server(server_index, discovery) {
                    refresh_note = Some(warning);
                }
            }
            Err(error) => {
                refresh_note = Some(format!(
                    "refresh failed: {}",
                    clean_one_line(&format!("{error:#}"))
                ));
            }
        }
    }
    match applied.result {
        Ok(()) => {
            let text = match refresh_note {
                Some(note) => format!("{ok_message} ({note})"),
                None => ok_message,
            };
            prompt::Feedback {
                text,
                is_error: false,
            }
        }
        Err(error) => prompt::Feedback {
            text: format!("{err_prefix}: {}", clean_one_line(&format!("{error:#}"))),
            is_error: true,
        },
    }
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
    let mut local_failed = false;
    match local_outcome {
        Ok(Some((server, result))) => {
            all_servers.push(server);
            all_results.push(result);
        }
        Ok(None) => {}
        Err(error) => {
            local_failed = true;
            warnings.push(clean_one_line(&format!("{error:#}")));
        }
    }
    all_servers.extend(servers);
    all_results.extend(discovered);
    let attempted_any = !all_servers.is_empty() || local_failed;

    let mut reachable_servers = Vec::new();
    let mut sessions = Vec::new();
    let mut choices = Vec::new();
    for (server, result) in all_servers.into_iter().zip(all_results) {
        match result {
            Ok(discovery) => {
                let server_name = clean_one_line(&server.name);
                if discovery.missing_views > 0 {
                    warnings.push(format!(
                        "{server_name}: could not list windows for {} session(s)",
                        discovery.missing_views
                    ));
                }
                let server_index = reachable_servers.len();
                let session_offset = sessions.len();
                for (session_id, label) in discovery.sessions {
                    sessions.push(SessionChoice {
                        server_index,
                        server_name: server_name.clone(),
                        session_id,
                        label,
                    });
                }
                for mut target in discovery.targets {
                    target.server_index = server_index;
                    target.session_index += session_offset;
                    choices.push(target);
                }
                reachable_servers.push(server);
            }
            Err(error) => warnings.push(format!(
                "{}: {}",
                clean_one_line(&server.name),
                clean_one_line(&format!("{error:#}"))
            )),
        }
    }

    DiscoveryOutcome {
        servers: reachable_servers,
        sessions,
        choices,
        warnings,
        attempted_any,
    }
}

async fn load_servers(server_config: &ServerConfig) -> Result<LoadedServers> {
    if let ServerConfig::Explicit(target) = server_config {
        return Ok(LoadedServers {
            servers: vec![config::resolve_server(target).await?.server],
            discover_local: false,
            has_configured_sources: true,
        });
    }

    let config = config::load_config()?;
    load_servers_with(server_config, &config, ServerAddress::local_or_loopback).await
}

async fn load_servers_with<F, Fut>(
    server_config: &ServerConfig,
    config: &config::Config,
    local: F,
) -> Result<LoadedServers>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ServerAddress>,
{
    if let ServerConfig::Explicit(target) = server_config {
        return Ok(LoadedServers {
            servers: vec![
                config::resolve_server_with(config, target, local)
                    .await?
                    .server,
            ],
            discover_local: false,
            has_configured_sources: true,
        });
    }

    let saved = config::parse_saved_servers(config, "pick");
    let mut servers = saved.servers;
    match server_config {
        ServerConfig::Explicit(_) => unreachable!(),
        ServerConfig::Env(target) => {
            match config::resolve_server_with(config, target, local).await {
                Ok(mut resolved)
                    if !servers
                        .iter()
                        .any(|saved| saved.address == resolved.server.address) =>
                {
                    if !resolved.named {
                        resolved.server.name = "REX_SERVER".to_owned();
                    }
                    servers.insert(0, resolved.server);
                }
                Ok(_) => {}
                Err(error) => eprintln!("zrex pick: {}", clean_one_line(&format!("{error:#}"))),
            }
            Ok(LoadedServers {
                servers,
                discover_local: false,
                has_configured_sources: true,
            })
        }
        ServerConfig::Default => Ok(LoadedServers {
            servers,
            discover_local: true,
            has_configured_sources: saved.configured > 0,
        }),
    }
}

async fn discover_until(server: &Server, deadline: Instant) -> Result<ServerDiscovery> {
    let (mut ctrl, _events) = timeout_at(deadline, Control::connect(&server.address, None))
        .await
        .context("discovery timed out")??;
    discover_with_control(&mut ctrl, server, deadline).await
}

async fn discover_with_control(
    ctrl: &mut Control,
    server: &Server,
    deadline: Instant,
) -> Result<ServerDiscovery> {
    let entries = timeout_at(deadline, session::list_all(ctrl))
        .await
        .context("discovery timed out")??;

    // Send all view requests before waiting, so one slow session does not
    // prevent other sessions on the same server from appearing.
    let mut sessions = Vec::new();
    let mut views = FuturesUnordered::new();
    for entry in &entries {
        let id = session::id_of(entry);
        if id.is_empty() {
            continue;
        }
        let session_index = sessions.len();
        let session_label = label_or_id(session::label_of(entry), &id);
        sessions.push((id.clone(), session_label.clone()));
        let reply = session::start_view(ctrl, &id);
        let server_name = server.name.clone();
        views.push(async move {
            let view = optional_reply(deadline, reply).await?;
            Some((
                session_index,
                targets(&server_name, session_index, &session_label, &id, &view),
            ))
        });
    }
    let mut missing_views = 0;
    let mut pending = Vec::new();
    while let Some(view) = views.next().await {
        if let Some((index, targets)) = view {
            // Start metadata queries as soon as this session's view arrives,
            // without waiting for other views or extending the server deadline.
            pending.push(describe_targets(ctrl, deadline, index, targets));
        } else {
            missing_views += 1;
        }
    }
    let mut groups = join_all(pending).await;
    groups.sort_unstable_by_key(|(index, _)| *index);
    Ok(ServerDiscovery {
        sessions,
        targets: groups
            .into_iter()
            .flat_map(|(_, targets)| targets)
            .collect(),
        missing_views,
    })
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
                target.process.clone_from(process);
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
    if clean.is_empty() || clean.eq_ignore_ascii_case("shell") || is_default_block_label(&clean) {
        None
    } else {
        Some(clean)
    }
}

fn is_default_block_label(label: &str) -> bool {
    label
        .strip_prefix("Block ")
        .is_some_and(|hex| hex.len() == 8 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn targets(
    server: &str,
    session_index: usize,
    session_label: &str,
    session_id: &str,
    view: &Value,
) -> Vec<Target> {
    let session = format!("[{}] {}", clean_one_line(server), session_label);
    let mut targets = Vec::new();
    let windows = session::windows(view);
    for (index, window) in windows.iter().enumerate() {
        let number = index + 1;
        let window_label = custom_window_label(&window.label);
        if window.blocks.len() > 1 {
            let block_count = window.blocks.len();
            for (split_index, block) in window.blocks.iter().enumerate() {
                let fallback = label_or_id(&block.label, &block.id);
                let block_label = custom_block_label(&block.label);
                let label_parts = TargetLabel {
                    prefix: format!("{session} / {number}.{}", split_index + 1),
                    window: window_label.clone(),
                    block: block_label.clone(),
                    fallback,
                };
                let label = label_parts.format(None);
                targets.push(Target {
                    server_index: 0,
                    session_index,
                    window_id: window.id.clone(),
                    window_number: number,
                    window_label: window_label.clone(),
                    window_block_count: block_count,
                    block_id: block.id.clone(),
                    block_number: split_index + 1,
                    block_label,
                    block_raw_label: clean_one_line(&block.label),
                    process: None,
                    label,
                    label_parts,
                    title: String::new(),
                    status: None,
                    session_id: session_id.to_owned(),
                });
            }
        } else if let Some(block_id) = window.active_or_first_block_id() {
            let block_label_str = window
                .blocks
                .iter()
                .find(|block| block.id == block_id)
                .map(|block| block.label.as_str())
                .unwrap_or_default();
            let block_raw_label = clean_one_line(block_label_str);
            let fallback = if block_raw_label.is_empty() {
                label_or_id(&window.label, &window.id)
            } else {
                block_raw_label.clone()
            };
            let block_label = custom_block_label(block_label_str);
            let label_parts = TargetLabel {
                prefix: format!("{session} / {number}"),
                window: window_label.clone(),
                block: block_label.clone(),
                fallback,
            };
            let label = label_parts.format(None);
            targets.push(Target {
                server_index: 0,
                session_index,
                window_id: window.id.clone(),
                window_number: number,
                window_label,
                window_block_count: 1,
                block_id: block_id.to_owned(),
                block_number: 1,
                block_label,
                block_raw_label,
                process: None,
                label,
                label_parts,
                title: String::new(),
                status: None,
                session_id: session_id.to_owned(),
            });
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

pub(super) fn styled_scope_row(
    tag: &str,
    target: &str,
    detail: &str,
    columns: usize,
) -> Vec<StyledSpan> {
    if columns == 0 {
        return Vec::new();
    }
    let ellipsis_width = '…'.width().unwrap_or(1);
    let mut spans = Vec::new();
    let tag_width = tag.width();
    if tag_width >= columns {
        let visible = prefix_to_columns(tag, columns.saturating_sub(ellipsis_width));
        if !visible.is_empty() {
            spans.push(StyledSpan {
                role: StyleRole::Title,
                text: visible,
                search_offset: None,
            });
        }
        if columns >= ellipsis_width {
            spans.push(StyledSpan {
                role: StyleRole::Title,
                text: "…".to_owned(),
                search_offset: None,
            });
        }
        return spans;
    }

    spans.push(StyledSpan {
        role: StyleRole::Title,
        text: tag.to_owned(),
        search_offset: None,
    });
    let remaining = columns - tag_width;

    if detail.is_empty() {
        let (visible, truncated) = if target.width() <= remaining {
            (target.to_owned(), false)
        } else {
            (
                prefix_to_columns(target, remaining.saturating_sub(ellipsis_width)),
                true,
            )
        };
        push_label_spans(&mut spans, &visible, 0, truncated);
        return spans;
    }

    let target_width = target.width();
    let detail_width = detail.width();
    if target_width + 1 + detail_width <= remaining {
        push_label_spans(&mut spans, target, 0, false);
        spans.push(StyledSpan {
            role: StyleRole::Title,
            text: format!(" {detail}"),
            search_offset: None,
        });
    } else if target_width + 1 + ellipsis_width < remaining {
        push_label_spans(&mut spans, target, 0, false);
        let detail_budget = remaining - target_width - 1;
        let visible = prefix_to_columns(detail, detail_budget.saturating_sub(ellipsis_width));
        if !visible.is_empty() {
            spans.push(StyledSpan {
                role: StyleRole::Title,
                text: format!(" {visible}…"),
                search_offset: None,
            });
        }
    } else {
        let (visible, truncated) = if target_width <= remaining {
            (target.to_owned(), false)
        } else {
            (
                prefix_to_columns(target, remaining.saturating_sub(ellipsis_width)),
                true,
            )
        };
        push_label_spans(&mut spans, &visible, 0, truncated);
    }
    spans
}

fn styled_label(text: &str, columns: usize) -> Vec<StyledSpan> {
    if columns == 0 || text.is_empty() {
        return Vec::new();
    }
    let mut spans = Vec::new();
    let (visible, truncated) = if text.width() <= columns {
        (text.to_owned(), false)
    } else {
        let ellipsis_width = '…'.width().unwrap_or(1);
        (
            prefix_to_columns(text, columns.saturating_sub(ellipsis_width)),
            true,
        )
    };
    push_label_spans(&mut spans, &visible, 0, truncated);
    spans
}

pub(super) fn prefix_to_columns(text: &str, max_columns: usize) -> String {
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
pub(super) fn test_target(
    server_index: usize,
    session_index: usize,
    label: &str,
    session_id: &str,
    block_id: &str,
) -> Target {
    test_target_full(
        server_index,
        session_index,
        label,
        session_id,
        "window:1",
        1,
        None,
        1,
        block_id,
        1,
        None,
        "shell",
        None,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn test_target_full(
    server_index: usize,
    session_index: usize,
    label: &str,
    session_id: &str,
    window_id: &str,
    window_number: usize,
    window_label: Option<&str>,
    window_block_count: usize,
    block_id: &str,
    block_number: usize,
    block_label: Option<&str>,
    block_raw_label: &str,
    process: Option<&str>,
) -> Target {
    Target {
        server_index,
        session_index,
        window_id: window_id.to_owned(),
        window_number,
        window_label: window_label.map(str::to_owned),
        window_block_count,
        block_id: block_id.to_owned(),
        block_number,
        block_label: block_label.map(str::to_owned),
        block_raw_label: block_raw_label.to_owned(),
        process: process.map(str::to_owned),
        label: label.to_owned(),
        label_parts: TargetLabel {
            prefix: label.to_owned(),
            window: window_label.map(str::to_owned),
            block: block_label.map(str::to_owned),
            fallback: String::new(),
        },
        title: String::new(),
        status: None,
        session_id: session_id.to_owned(),
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
            server_index: 0,
            session_index: 0,
            window_id: "window:1".to_owned(),
            window_number: 1,
            window_label: None,
            window_block_count: 1,
            block_id: "block:1".to_owned(),
            block_number: 1,
            block_label: None,
            block_raw_label: "shell".to_owned(),
            process: None,
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
        let list = targets("local", 0, "zrex", "session:1", &view);
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

        assert_eq!(outcome.servers.len(), 1);
        assert_eq!(outcome.servers[0].name, "office");
        assert_eq!(outcome.sessions.len(), 1);
        assert_eq!(outcome.sessions[0].display_name(), "[office] work");
        assert_eq!(outcome.choices.len(), 1);
        assert_eq!(outcome.choices[0].server_index, 0);
        assert_eq!(outcome.choices[0].session_index, 0);
        assert_eq!(outcome.choices[0].label, "[office] work / 1 dev");
        assert_eq!(outcome.warnings.len(), 1);
        assert!(outcome.warnings[0].starts_with("dead: "));
    }

    #[tokio::test]
    async fn discover_all_keeps_reachable_empty_server_for_new_session_creation() {
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
                    "session.attach_all" => json!({"sessions": []}),
                    other => panic!("unexpected method {other}"),
                };
                ws.send(Message::text(
                    json!({"type": "response", "id": id, "seq": 0, "payload": payload}).to_string(),
                ))
                .await
                .unwrap();
            }
        });

        let servers = vec![Server {
            name: "fresh".to_owned(),
            address: format!("http://{live_addr}").parse().unwrap(),
        }];

        let outcome = discover_all(
            servers,
            Some(async { None }),
            Instant::now() + DISCOVERY_TIME,
        )
        .await;

        assert_eq!(outcome.servers.len(), 1);
        assert_eq!(outcome.servers[0].name, "fresh");
        assert!(outcome.sessions.is_empty());
        assert!(outcome.choices.is_empty());
        assert!(outcome.warnings.is_empty());
    }

    #[tokio::test]
    async fn load_servers_resolves_explicit_and_env_aliases_and_deduplicates() {
        let mut config = config::Config::default();
        config
            .servers
            .insert("mac".to_owned(), "https://mac.tail.ts.net".to_owned());
        config
            .servers
            .insert("office".to_owned(), "https://office.example".to_owned());
        let fake_local = || async { "http://127.0.0.1:7297".parse::<ServerAddress>().unwrap() };

        // Explicit saved alias selects only that server and keeps its alias name.
        let loaded = load_servers_with(
            &ServerConfig::Explicit("mac".to_owned()),
            &config,
            fake_local,
        )
        .await
        .unwrap();
        assert!(!loaded.discover_local);
        assert!(loaded.has_configured_sources);
        assert_eq!(
            loaded.servers,
            vec![Server {
                name: "mac".to_owned(),
                address: "https://mac.tail.ts.net".parse().unwrap(),
            }]
        );

        // Explicit `local` resolves to the local server without scanning other saved servers.
        let loaded = load_servers_with(
            &ServerConfig::Explicit("local".to_owned()),
            &config,
            fake_local,
        )
        .await
        .unwrap();
        assert!(!loaded.discover_local);
        assert!(loaded.has_configured_sources);
        assert_eq!(
            loaded.servers,
            vec![Server {
                name: "local".to_owned(),
                address: "http://127.0.0.1:7297".parse().unwrap(),
            }]
        );

        // REX_SERVER set to a saved alias deduplicates against saved servers.
        let loaded = load_servers_with(&ServerConfig::Env("mac".to_owned()), &config, fake_local)
            .await
            .unwrap();
        assert!(!loaded.discover_local);
        assert!(loaded.has_configured_sources);
        assert_eq!(
            loaded
                .servers
                .iter()
                .map(|server| server.name.as_str())
                .collect::<Vec<_>>(),
            vec!["mac", "office"]
        );

        // REX_SERVER set to a direct URL prepends [REX_SERVER].
        let loaded = load_servers_with(
            &ServerConfig::Env("https://extra.example".to_owned()),
            &config,
            fake_local,
        )
        .await
        .unwrap();
        assert!(!loaded.discover_local);
        assert!(loaded.has_configured_sources);
        assert_eq!(
            loaded
                .servers
                .iter()
                .map(|server| server.name.as_str())
                .collect::<Vec<_>>(),
            vec!["REX_SERVER", "mac", "office"]
        );
    }

    #[tokio::test]
    async fn distinguishes_no_server_sources_from_unreachable_or_invalid_sources() {
        let fake_local = || async { "http://127.0.0.1:7297".parse::<ServerAddress>().unwrap() };

        // 1. Default config with no saved servers and no running local server -> no sources.
        let empty_config = config::Config::default();
        let loaded = load_servers_with(&ServerConfig::Default, &empty_config, fake_local)
            .await
            .unwrap();
        assert!(loaded.discover_local);
        assert!(!loaded.has_configured_sources);
        assert!(loaded.servers.is_empty());

        let outcome = discover_all(
            loaded.servers,
            Some(async { None }),
            Instant::now() + DISCOVERY_TIME,
        )
        .await;
        assert!(outcome.servers.is_empty());
        assert!(outcome.warnings.is_empty());
        assert!(outcome.has_no_sources(loaded.has_configured_sources));

        // 2. Default config with an invalid saved server URL -> configured source exists.
        let mut invalid_config = config::Config::default();
        invalid_config
            .servers
            .insert("broken".to_owned(), "ftp://bad.example".to_owned());
        let loaded = load_servers_with(&ServerConfig::Default, &invalid_config, fake_local)
            .await
            .unwrap();
        assert!(loaded.has_configured_sources);
        assert!(loaded.servers.is_empty());
        let outcome = discover_all(
            loaded.servers,
            Some(async { None }),
            Instant::now() + DISCOVERY_TIME,
        )
        .await;
        assert!(!outcome.has_no_sources(loaded.has_configured_sources));

        // 3. Invalid REX_SERVER with empty config -> configured source exists.
        let loaded = load_servers_with(
            &ServerConfig::Env("ftp://bad.example".to_owned()),
            &empty_config,
            fake_local,
        )
        .await
        .unwrap();
        assert!(loaded.has_configured_sources);
        assert!(!loaded.discover_local);
        assert!(loaded.servers.is_empty());
        let outcome = discover_all(
            loaded.servers,
            Option::<std::future::Ready<Option<ServerAddress>>>::None,
            Instant::now() + DISCOVERY_TIME,
        )
        .await;
        assert!(!outcome.has_no_sources(loaded.has_configured_sources));

        // 4. Running local server detected, but fails to connect -> source existed.
        let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr: ServerAddress = format!("http://{}", dead_listener.local_addr().unwrap())
            .parse()
            .unwrap();
        drop(dead_listener);
        let outcome = discover_all(
            Vec::new(),
            Some(async move { Some(dead_addr) }),
            Instant::now() + DISCOVERY_TIME,
        )
        .await;
        assert!(outcome.servers.is_empty());
        assert_eq!(outcome.warnings.len(), 1);
        assert!(!outcome.has_no_sources(false));

        // 5. Local probe times out -> do not mask timeout as no sources.
        let outcome = discover_all(
            Vec::new(),
            Some(std::future::pending::<Option<ServerAddress>>()),
            Instant::now() + Duration::from_millis(10),
        )
        .await;
        assert!(outcome.servers.is_empty());
        assert_eq!(outcome.warnings.len(), 1);
        assert!(!outcome.has_no_sources(false));

        // 6. Explicit -S against an unreachable server -> always an error, never intro.
        let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_url = format!("http://{}", dead_listener.local_addr().unwrap());
        drop(dead_listener);
        let loaded = load_servers_with(
            &ServerConfig::Explicit(dead_url),
            &empty_config,
            fake_local,
        )
        .await
        .unwrap();
        assert!(loaded.has_configured_sources);
        assert!(!loaded.discover_local);
        let outcome = discover_all(
            loaded.servers,
            Option::<std::future::Ready<Option<ServerAddress>>>::None,
            Instant::now() + DISCOVERY_TIME,
        )
        .await;
        assert!(outcome.servers.is_empty());
        assert_eq!(outcome.warnings.len(), 1);
        assert!(!outcome.has_no_sources(loaded.has_configured_sources));
    }

    #[test]
    fn custom_block_label_hides_default_shell_and_block_id_labels() {
        assert_eq!(custom_block_label("shell"), None);
        assert_eq!(custom_block_label("SHELL"), None);
        assert_eq!(custom_block_label("Block 89abcdef"), None);
        assert_eq!(custom_block_label("Block 1234ABCD"), None);
        assert_eq!(
            custom_block_label("Block short"),
            Some("Block short".to_owned())
        );
        assert_eq!(custom_block_label("editor"), Some("editor".to_owned()));
    }

    #[tokio::test]
    async fn apply_manage_renames_and_kills_and_refreshes_server_in_place() {
        use std::sync::{Arc, Mutex};

        use futures_util::SinkExt;
        use tokio::net::TcpListener;
        use tokio_tungstenite::accept_hdr_async;
        use tokio_tungstenite::tungstenite::Message;
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

        #[derive(Clone)]
        struct FakeState {
            session_label: String,
            window_label: String,
            block_label: String,
            has_block2: bool,
            has_window: bool,
            has_session: bool,
            calls: Vec<String>,
        }

        let state = Arc::new(Mutex::new(FakeState {
            session_label: "work".to_owned(),
            window_label: "dev".to_owned(),
            block_label: "editor".to_owned(),
            has_block2: true,
            has_window: true,
            has_session: true,
            calls: Vec::new(),
        }));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_state = Arc::clone(&state);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let st = Arc::clone(&server_state);
                tokio::spawn(async move {
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
                        let method = req["method"].as_str().unwrap();
                        let payload = {
                            let mut s = st.lock().unwrap();
                            s.calls.push(method.to_owned());
                            match method {
                                "session.attach" => json!({"session_id": "session:1"}),
                                "session.set_label" => {
                                    s.session_label =
                                        req["payload"]["label"].as_str().unwrap().to_owned();
                                    json!({"revision": 1})
                                }
                                "session.set_window_label" => {
                                    s.window_label =
                                        req["payload"]["label"].as_str().unwrap().to_owned();
                                    json!({"revision": 2})
                                }
                                "session.set_block_label" => {
                                    s.block_label =
                                        req["payload"]["label"].as_str().unwrap().to_owned();
                                    json!({"revision": 3})
                                }
                                "block.close" => {
                                    assert_eq!(req["payload"]["block_id"], "block:2");
                                    s.has_block2 = false;
                                    json!({"block_id": "block:2", "revision": 4})
                                }
                                "session.close_window" => {
                                    assert_eq!(req["payload"]["window_id"], "window:1");
                                    s.has_window = false;
                                    json!({"revision": 5})
                                }
                                "session.destroy" => {
                                    assert_eq!(req["payload"]["session_id"], "session:1");
                                    s.has_session = false;
                                    json!({})
                                }
                                "session.attach_all" => {
                                    if s.has_session {
                                        json!({"sessions": [{"session_id": "session:1", "label": s.session_label}]})
                                    } else {
                                        json!({"sessions": []})
                                    }
                                }
                                "session.view" => {
                                    if s.has_window {
                                        let mut blocks = vec![
                                            json!({"block_id": "block:1", "label": s.block_label}),
                                        ];
                                        if s.has_block2 {
                                            blocks.push(
                                                json!({"block_id": "block:2", "label": "shell"}),
                                            );
                                        }
                                        json!({
                                            "active_window_id": "window:1",
                                            "windows": [{
                                                "window_id": "window:1",
                                                "label": s.window_label,
                                                "focused_block_id": "block:1",
                                                "layers": [{"blocks": blocks}]
                                            }]
                                        })
                                    } else {
                                        json!({"windows": []})
                                    }
                                }
                                "com.superlogical.terminal.title" => json!({"title": ""}),
                                "com.superlogical.terminal.program_status" => {
                                    json!({"records": []})
                                }
                                "com.superlogical.terminal.process" => {
                                    json!({"foreground": null, "child": null})
                                }
                                other => panic!("unexpected method {other}"),
                            }
                        };
                        ws.send(Message::text(
                            json!({"type": "response", "id": id, "seq": 0, "payload": payload})
                                .to_string(),
                        ))
                        .await
                        .unwrap();
                    }
                });
            }
        });

        let server = Server {
            name: "office".to_owned(),
            address: format!("http://{addr}").parse().unwrap(),
        };
        let other_server = Server {
            name: "other".to_owned(),
            address: "http://127.0.0.1:1".parse().unwrap(),
        };
        let initial = discover_until(&server, Instant::now() + DISCOVERY_TIME)
            .await
            .unwrap();
        let mut outcome = DiscoveryOutcome {
            servers: vec![
                Server {
                    name: server.name.clone(),
                    address: format!("http://{addr}").parse().unwrap(),
                },
                other_server,
            ],
            sessions: vec![
                SessionChoice {
                    server_index: 0,
                    server_name: "office".to_owned(),
                    session_id: "session:1".to_owned(),
                    label: "work".to_owned(),
                },
                SessionChoice {
                    server_index: 1,
                    server_name: "other".to_owned(),
                    session_id: "session:other".to_owned(),
                    label: "keep".to_owned(),
                },
            ],
            choices: {
                let mut c = initial.targets;
                c.push(test_target(
                    1,
                    1,
                    "[other] keep / 1 zsh",
                    "session:other",
                    "block:other",
                ));
                c
            },
            warnings: Vec::new(),
            attempted_any: true,
        };

        // 1. Rename session.
        let applied = apply_manage(
            &outcome.servers[0],
            ManageOp::Rename {
                target: &ManageTarget::Session {
                    server_index: 0,
                    session_id: "session:1".to_owned(),
                },
                label: "core",
            },
            Instant::now() + DISCOVERY_TIME,
            DISCOVERY_TIME,
        )
        .await;
        let fb = finish_manage(
            &mut outcome,
            0,
            applied,
            "Renamed session".to_owned(),
            "Rename failed",
        );
        assert!(!fb.is_error);
        assert_eq!(outcome.sessions[0].label, "core");
        // Other server's session and target remain intact with valid session_index.
        assert_eq!(outcome.sessions[1].label, "keep");
        let other_target = outcome
            .choices
            .iter()
            .find(|t| t.server_index == 1)
            .unwrap();
        assert_eq!(other_target.session_index, 1);

        // 2. Rename window.
        let applied = apply_manage(
            &outcome.servers[0],
            ManageOp::Rename {
                target: &ManageTarget::Window {
                    server_index: 0,
                    session_id: "session:1".to_owned(),
                    window_id: "window:1".to_owned(),
                },
                label: "api",
            },
            Instant::now() + DISCOVERY_TIME,
            DISCOVERY_TIME,
        )
        .await;
        let fb = finish_manage(
            &mut outcome,
            0,
            applied,
            "Renamed window".to_owned(),
            "Rename failed",
        );
        assert!(!fb.is_error);
        assert_eq!(outcome.choices[0].window_label.as_deref(), Some("api"));

        // 3. Rename block.
        let applied = apply_manage(
            &outcome.servers[0],
            ManageOp::Rename {
                target: &ManageTarget::Block {
                    server_index: 0,
                    session_id: "session:1".to_owned(),
                    block_id: "block:1".to_owned(),
                },
                label: "tests",
            },
            Instant::now() + DISCOVERY_TIME,
            DISCOVERY_TIME,
        )
        .await;
        let fb = finish_manage(
            &mut outcome,
            0,
            applied,
            "Renamed block".to_owned(),
            "Rename failed",
        );
        assert!(!fb.is_error);
        assert_eq!(outcome.choices[0].block_label.as_deref(), Some("tests"));
        assert_eq!(outcome.choices[0].label, "[office] core / 1.1 api / tests");

        // 4. Kill block:2 -> window now has 1 block.
        let applied = apply_manage(
            &outcome.servers[0],
            ManageOp::Kill {
                target: &ManageTarget::Block {
                    server_index: 0,
                    session_id: "session:1".to_owned(),
                    block_id: "block:2".to_owned(),
                },
            },
            Instant::now() + DISCOVERY_TIME,
            DISCOVERY_TIME,
        )
        .await;
        let fb = finish_manage(
            &mut outcome,
            0,
            applied,
            "Closed block".to_owned(),
            "Kill failed",
        );
        assert!(!fb.is_error);
        assert_eq!(
            outcome
                .choices
                .iter()
                .filter(|t| t.server_index == 0)
                .count(),
            1
        );
        assert_eq!(outcome.choices[0].window_block_count, 1);

        // 5. Kill window:1 -> session:1 remains with 0 windows.
        let applied = apply_manage(
            &outcome.servers[0],
            ManageOp::Kill {
                target: &ManageTarget::Window {
                    server_index: 0,
                    session_id: "session:1".to_owned(),
                    window_id: "window:1".to_owned(),
                },
            },
            Instant::now() + DISCOVERY_TIME,
            DISCOVERY_TIME,
        )
        .await;
        let fb = finish_manage(
            &mut outcome,
            0,
            applied,
            "Closed window".to_owned(),
            "Kill failed",
        );
        assert!(!fb.is_error);
        assert_eq!(
            outcome
                .choices
                .iter()
                .filter(|t| t.server_index == 0)
                .count(),
            0
        );
        assert_eq!(
            outcome
                .sessions
                .iter()
                .filter(|s| s.server_index == 0)
                .count(),
            1
        );

        // 6. Kill session:1 -> server 0 has 0 sessions, server 1 target's session_index remaps to 0.
        let applied = apply_manage(
            &outcome.servers[0],
            ManageOp::Kill {
                target: &ManageTarget::Session {
                    server_index: 0,
                    session_id: "session:1".to_owned(),
                },
            },
            Instant::now() + DISCOVERY_TIME,
            DISCOVERY_TIME,
        )
        .await;
        let fb = finish_manage(
            &mut outcome,
            0,
            applied,
            "Destroyed session".to_owned(),
            "Kill failed",
        );
        assert!(!fb.is_error);
        assert_eq!(outcome.sessions.len(), 1);
        assert_eq!(outcome.sessions[0].server_index, 1);
        assert_eq!(outcome.choices.len(), 1);
        assert_eq!(outcome.choices[0].server_index, 1);
        assert_eq!(outcome.choices[0].session_index, 0);
    }
}
