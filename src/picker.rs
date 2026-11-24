mod prompt;

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::{StreamExt, future::join_all, stream::FuturesUnordered};
use serde_json::{Value, json};
use tokio::time::{Duration, Instant, timeout_at};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::app;
use crate::config::{self, DISCOVERY_TIME, Server, ServerConfig};
use crate::discovery::{LocalDiscovery, NO_SERVER_FOUND, fan_out, probe_local};
use crate::rex::{BlockRef, ServerAddress, control::Control, proto::ApiError};
use crate::session;
use crate::text::{clean_one_line, clean_truncated, truncate_to_columns};

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
pub(super) struct ManageTarget {
    server_index: usize,
    session_id: String,
    scope: ManageScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ManageScope {
    Session,
    Window(String),
    Block(String),
}

impl ManageScope {
    fn label(&self) -> &'static str {
        match self {
            Self::Session => "Session",
            Self::Window(_) => "Window",
            Self::Block(_) => "Block",
        }
    }

    fn kind_name(&self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Window(_) => "window",
            Self::Block(_) => "block",
        }
    }
}

impl ManageTarget {
    fn kind_name(&self) -> &'static str {
        self.scope.kind_name()
    }

    fn kill_progress_message(&self) -> String {
        match &self.scope {
            ManageScope::Session => "Destroying session…".to_owned(),
            ManageScope::Window(_) | ManageScope::Block(_) => {
                format!("Closing {}…", self.kind_name())
            }
        }
    }

    fn kill_done_message(&self) -> String {
        match &self.scope {
            ManageScope::Session => "Destroyed session".to_owned(),
            ManageScope::Window(_) | ManageScope::Block(_) => {
                format!("Closed {}", self.kind_name())
            }
        }
    }

    async fn rename(&self, ctrl: &mut Control, label: &str) -> Result<()> {
        match &self.scope {
            ManageScope::Session => session::set_label(ctrl, &self.session_id, label).await,
            ManageScope::Window(window_id) => {
                session::set_window_label(ctrl, &self.session_id, window_id, label).await
            }
            ManageScope::Block(block_id) => {
                session::set_block_label(ctrl, BlockRef::new(&self.session_id, block_id), label)
                    .await
            }
        }
    }

    async fn kill(&self, ctrl: &mut Control) -> Result<()> {
        match &self.scope {
            ManageScope::Session => session::destroy(ctrl, &self.session_id).await,
            ManageScope::Window(window_id) => {
                session::close_window(ctrl, &self.session_id, window_id).await
            }
            ManageScope::Block(block_id) => {
                session::close_block(ctrl, BlockRef::new(&self.session_id, block_id)).await
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TargetKey {
    session_id: String,
    window_id: String,
    block_id: String,
}

impl TargetKey {
    pub(super) fn matches_block(&self, target: &Target) -> bool {
        self.matches_window(target) && target.block_id == self.block_id
    }

    pub(super) fn matches_window(&self, target: &Target) -> bool {
        target.session_id == self.session_id && target.window_id == self.window_id
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

pub(super) struct DiscoveryOutcome {
    servers: Vec<Server>,
    sessions: Vec<SessionChoice>,
    choices: Vec<Target>,
    warnings: Vec<String>,
    attempted_any: bool,
}

#[derive(Clone)]
struct LoadedServers {
    servers: Vec<Server>,
    local_discovery: LocalDiscovery,
    has_configured_sources: bool,
}

struct ServerDiscovery {
    sessions: Vec<(String, String)>,
    targets: Vec<Target>,
    missing_views: usize,
}

fn missing_views_warning(server_name: &str, missing_views: usize) -> Option<String> {
    (missing_views > 0)
        .then(|| format!("{server_name}: could not list windows for {missing_views} session(s)"))
}

impl DiscoveryOutcome {
    fn has_no_sources(&self, has_configured_sources: bool) -> bool {
        !has_configured_sources && !self.attempted_any
    }

    fn unreachable_error(&self) -> String {
        match self.warnings.as_slice() {
            [single] => single.clone(),
            _ => "no reachable servers".to_owned(),
        }
    }

    fn replace_server(
        &mut self,
        server_index: usize,
        discovery: ServerDiscovery,
    ) -> Option<String> {
        let server_name = clean_one_line(&self.servers[server_index].name);
        let warning = missing_views_warning(&server_name, discovery.missing_views);

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

fn discovery_warning_feedback(warnings: &[String]) -> Option<prompt::Feedback> {
    let first = warnings.first()?;
    let text = match warnings.len() {
        1 => first.clone(),
        len => {
            let rest = len - 1;
            format!(
                "{first} (and {rest} more server warning{})",
                if rest == 1 { "" } else { "s" }
            )
        }
    };
    Some(prompt::Feedback {
        text,
        is_error: true,
    })
}

#[derive(Debug, PartialEq, Eq)]
enum PostAttach {
    Quit,
    Return {
        focus: Option<prompt::FocusTarget>,
        feedback: Option<prompt::Feedback>,
    },
}

impl PostAttach {
    fn with_feedback(text: String, is_error: bool) -> Self {
        Self::Return {
            focus: None,
            feedback: Some(prompt::Feedback { text, is_error }),
        }
    }
}

fn capitalize_first(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn format_prefixed_error(prefix: &str, error: &anyhow::Error) -> String {
    format!("{prefix}: {}", clean_one_line(&format!("{error:#}")))
}

fn classify_attach_result(
    error_prefix: &str,
    server_name: String,
    result: Result<app::AttachExit>,
) -> PostAttach {
    match result {
        Ok(app::AttachExit::Detached {
            double_detach: true,
            ..
        }) => PostAttach::Quit,
        Ok(app::AttachExit::Detached {
            session_id,
            block_id,
            double_detach: false,
        }) => PostAttach::Return {
            focus: Some(prompt::FocusTarget {
                server_name,
                session_id,
                block_id,
            }),
            feedback: None,
        },
        Ok(exit @ (app::AttachExit::BlockClosed | app::AttachExit::SessionClosed)) => {
            PostAttach::with_feedback(
                capitalize_first(exit.closed_message().expect("closed exit has message")),
                false,
            )
        }
        Err(error) => PostAttach::with_feedback(format_prefixed_error(error_prefix, &error), true),
    }
}

async fn execute_attach(
    outcome: &DiscoveryOutcome,
    selection: prompt::AttachSelection,
) -> (&'static str, String, Result<app::AttachExit>) {
    match selection {
        prompt::AttachSelection::Existing(index) => {
            let target = &outcome.choices[index];
            let server = &outcome.servers[target.server_index];
            let name = clean_one_line(&server.name);
            let res =
                app::attach_existing(&server.address, &target.session_id, &target.block_id).await;
            ("Attach failed", name, res)
        }
        prompt::AttachSelection::NewSession {
            server_index,
            label,
        } => {
            let server = &outcome.servers[server_index];
            let name = clean_one_line(&server.name);
            let res = app::attach_new_session(&server.address, label.as_deref()).await;
            ("Create session failed", name, res)
        }
        prompt::AttachSelection::NewWindow {
            session_index,
            label,
        } => {
            let session = &outcome.sessions[session_index];
            let server = &outcome.servers[session.server_index];
            let name = clean_one_line(&server.name);
            let res =
                app::attach_new_window(&server.address, &session.session_id, label.as_deref())
                    .await;
            ("Create window failed", name, res)
        }
    }
}

type RefreshFuture = Pin<Box<dyn Future<Output = DiscoveryOutcome>>>;

enum RefreshState {
    Idle,
    InFlight(RefreshFuture),
    Ready(DiscoveryOutcome),
}

impl RefreshState {
    fn clear(&mut self) {
        *self = Self::Idle;
    }

    fn take_ready(&mut self) -> Option<DiscoveryOutcome> {
        if matches!(self, Self::Ready(_)) {
            match std::mem::replace(self, Self::Idle) {
                Self::Ready(outcome) => Some(outcome),
                _ => unreachable!(),
            }
        } else {
            None
        }
    }
}

fn start_refresh(loaded: &LoadedServers) -> RefreshFuture {
    let servers = loaded.servers.clone();
    let local_discovery = loaded.local_discovery;
    Box::pin(async move {
        let deadline = Instant::now() + DISCOVERY_TIME;
        discover_all(
            servers,
            local_discovery,
            async move |excluded| probe_local(local_discovery, excluded).await,
            deadline,
        )
        .await
    })
}

fn apply_refresh_outcome(
    outcome: &mut DiscoveryOutcome,
    state: &mut prompt::PickerState,
    refreshed: DiscoveryOutcome,
) {
    if refreshed.servers.is_empty() {
        let message = if refreshed.warnings.is_empty() {
            "No Rex servers reachable".to_owned()
        } else {
            refreshed.unreachable_error()
        };
        state.finish_refresh_error(prompt::Feedback {
            text: message,
            is_error: true,
        });
        return;
    }
    let warning = discovery_warning_feedback(&refreshed.warnings);
    let server_names: Vec<String> = refreshed
        .servers
        .iter()
        .map(|server| clean_one_line(&server.name))
        .collect();
    *outcome = refreshed;
    state.apply_discovery(
        outcome.choices.clone(),
        outcome.sessions.clone(),
        server_names,
        warning,
    );
}

pub async fn run(server_config: &ServerConfig) -> Result<()> {
    app::ensure_terminal()?;
    let loaded = load_servers(server_config).await?;
    let mut outcome = start_refresh(&loaded).await;
    if outcome.servers.is_empty() {
        if outcome.has_no_sources(loaded.has_configured_sources) {
            bail!("{NO_SERVER_FOUND}");
        }
        if outcome.warnings.len() > 1 {
            for warning in &outcome.warnings {
                eprintln!("zrex pick: {warning}");
            }
        }
        bail!("{}", outcome.unreachable_error());
    }
    let initial_feedback = discovery_warning_feedback(&outcome.warnings);
    for warning in outcome.warnings.drain(..) {
        eprintln!("zrex pick: {warning}");
    }

    let server_names: Vec<String> = outcome
        .servers
        .iter()
        .map(|server| clean_one_line(&server.name))
        .collect();

    let raw_mode = prompt::RawModeGuard::enter()?;
    let mut screen = prompt::Screen::enter(&raw_mode)?;
    let mut state = prompt::PickerState::new(
        outcome.choices.clone(),
        outcome.sessions.clone(),
        server_names,
    );
    if let Some(feedback) = initial_feedback {
        state.set_feedback(feedback);
    }

    let mut refresh = RefreshState::Idle;

    loop {
        if state.is_attach_mode()
            && let Some(refreshed) = refresh.take_ready()
        {
            apply_refresh_outcome(&mut outcome, &mut state, refreshed);
        }

        let step = match &mut refresh {
            RefreshState::InFlight(future) => screen.step_until(&mut state, future).await?,
            RefreshState::Idle | RefreshState::Ready(_) => screen.step(&mut state)?,
        };

        match step {
            prompt::StepEvent::Cancel => return Ok(()),
            prompt::StepEvent::Refreshed(refreshed) => {
                if state.is_attach_mode() {
                    refresh.clear();
                    apply_refresh_outcome(&mut outcome, &mut state, refreshed);
                } else {
                    state.clear_refreshing();
                    refresh = RefreshState::Ready(refreshed);
                }
            }
            prompt::StepEvent::Selected(prompt::Selection::Attach(selection)) => {
                refresh.clear();
                drop(screen);
                let (error_prefix, server_name, result) = execute_attach(&outcome, selection).await;
                match classify_attach_result(error_prefix, server_name, result) {
                    PostAttach::Quit => return Ok(()),
                    PostAttach::Return { focus, feedback } => {
                        if prompt::take_queued_quit_key()? {
                            return Ok(());
                        }
                        screen = prompt::Screen::enter(&raw_mode)?;
                        state.reset_after_attach(focus, feedback);
                        refresh = RefreshState::InFlight(start_refresh(&loaded));
                    }
                }
            }
            prompt::StepEvent::Selected(prompt::Selection::Rename { target, label }) => {
                refresh.clear();
                run_manage_op(
                    &mut screen,
                    &mut state,
                    &mut outcome,
                    ManageOp::Rename {
                        target: &target,
                        label: &label,
                    },
                )
                .await?;
            }
            prompt::StepEvent::Selected(prompt::Selection::Kill { target }) => {
                refresh.clear();
                run_manage_op(
                    &mut screen,
                    &mut state,
                    &mut outcome,
                    ManageOp::Kill { target: &target },
                )
                .await?;
            }
        }
    }
}

async fn run_manage_op(
    screen: &mut prompt::Screen,
    state: &mut prompt::PickerState,
    outcome: &mut DiscoveryOutcome,
    op: ManageOp<'_>,
) -> Result<()> {
    let busy = op.busy_message();
    let ok_msg = op.ok_message();
    let err_prefix = op.err_prefix();
    let server_index = op.target().server_index;
    screen.render_busy(state, &busy)?;
    let applied = apply_manage(
        &outcome.servers[server_index],
        op,
        Instant::now() + DISCOVERY_TIME,
        DISCOVERY_TIME,
    )
    .await;
    let feedback = finish_manage(outcome, server_index, applied, ok_msg, &err_prefix);
    state.refresh(outcome.choices.clone(), outcome.sessions.clone(), feedback);
    screen.drain_input()?;
    Ok(())
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

impl<'a> ManageOp<'a> {
    fn target(&self) -> &'a ManageTarget {
        match self {
            Self::Rename { target, .. } | Self::Kill { target } => target,
        }
    }

    fn busy_message(&self) -> String {
        match self {
            Self::Rename { target, .. } => format!("Renaming {}…", target.kind_name()),
            Self::Kill { target } => target.kill_progress_message(),
        }
    }

    fn ok_message(&self) -> String {
        match self {
            Self::Rename { target, label } => {
                let kind = target.kind_name();
                if label.is_empty() {
                    format!("Reset {kind} name to default")
                } else {
                    format!("Renamed {kind} to {}", clean_one_line(label))
                }
            }
            Self::Kill { target } => target.kill_done_message(),
        }
    }

    fn err_prefix(&self) -> String {
        match self {
            Self::Rename { target, .. } => format!("Rename {} failed", target.kind_name()),
            Self::Kill { target } => format!("Kill {} failed", target.kind_name()),
        }
    }
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
        session::attach(&mut ctrl, &op.target().session_id).await?;
        match op {
            ManageOp::Rename { target, label } => target.rename(&mut ctrl, label).await,
            ManageOp::Kill { target } => target.kill(&mut ctrl).await,
        }
    })
    .await
    .map_err(|_| anyhow!("operation timed out"))
    .and_then(|inner| inner);

    let should_refresh = match &result {
        Ok(()) => true,
        Err(error) => error.downcast_ref::<ApiError>().is_some_and(|api| {
            matches!(api.status, 404 | 409)
                || matches!(
                    api.code.as_str(),
                    "not_found"
                        | "session_not_found"
                        | "window_not_found"
                        | "block_not_found"
                        | "conflict"
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
                refresh_note = Some(format_prefixed_error("refresh failed", &error));
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
            text: format_prefixed_error(err_prefix, &error),
            is_error: true,
        },
    }
}

async fn discover_all<F>(
    servers: Vec<Server>,
    local_discovery: LocalDiscovery,
    local_probe: F,
    deadline: Instant,
) -> DiscoveryOutcome
where
    F: AsyncFnOnce(&[ServerAddress]) -> Result<Option<(ServerAddress, Control)>>,
{
    let fan = fan_out(
        servers,
        local_discovery,
        local_probe,
        deadline,
        "discovery timed out",
        |server, mut ctrl, deadline| async move {
            discover_with_control(&mut ctrl, &server, deadline).await
        },
    )
    .await;

    let mut warnings = Vec::new();
    if let Some(error) = fan.local_error {
        warnings.push(error);
    }

    let mut reachable_servers = Vec::new();
    let mut sessions = Vec::new();
    let mut choices = Vec::new();
    for (server, result) in fan.entries {
        match result {
            Ok(discovery) => {
                let server_name = clean_one_line(&server.name);
                if let Some(warning) = missing_views_warning(&server_name, discovery.missing_views)
                {
                    warnings.push(warning);
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
        attempted_any: fan.attempted_any,
    }
}

async fn load_servers(server_config: &ServerConfig) -> Result<LoadedServers> {
    if let ServerConfig::Explicit(target) = server_config {
        if config::is_builtin_local(target) {
            return Ok(LoadedServers {
                servers: Vec::new(),
                local_discovery: LocalDiscovery::Required,
                has_configured_sources: true,
            });
        }
        if target.is_empty() || target.contains("://") {
            return Ok(LoadedServers {
                servers: vec![config::resolve_server(target).await?.server],
                local_discovery: LocalDiscovery::None,
                has_configured_sources: true,
            });
        }
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
        if config::is_builtin_local(target) {
            return Ok(LoadedServers {
                servers: Vec::new(),
                local_discovery: LocalDiscovery::Required,
                has_configured_sources: true,
            });
        }
        return Ok(LoadedServers {
            servers: vec![
                config::resolve_server_with(config, target, local)
                    .await?
                    .server,
            ],
            local_discovery: LocalDiscovery::None,
            has_configured_sources: true,
        });
    }

    let saved = config::parse_saved_servers(config, "pick");
    let mut servers = saved.servers;
    match server_config {
        ServerConfig::Explicit(_) => unreachable!(),
        ServerConfig::Env(target) => {
            let local_discovery = if config::is_builtin_local(target) {
                LocalDiscovery::Required
            } else {
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
                LocalDiscovery::None
            };
            Ok(LoadedServers {
                servers,
                local_discovery,
                has_configured_sources: true,
            })
        }
        ServerConfig::Default => Ok(LoadedServers {
            servers,
            local_discovery: LocalDiscovery::Optional,
            has_configured_sources: saved.configured > 0,
        }),
    }
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
            let view = session::optional_reply(reply, deadline).await?;
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
            let block = BlockRef::new(&target.session_id, &target.block_id);
            let title = session::start_terminal_title(ctrl, block);
            let status = ctrl.start_call(
                "com.superlogical.terminal.program_status",
                json!({"session_id": block.session_id, "block_id": block.block_id}),
            );
            let process = session::start_terminal_process(ctrl, block);
            (title, status, process)
        });
    }
    async move {
        let details: HashMap<_, _> = join_all(requests.into_iter().map(
            |(id, (title, status, process))| async move {
                let (title, status, process) = tokio::join!(
                    session::optional_reply(title, deadline),
                    session::optional_reply(status, deadline),
                    session::optional_reply(process, deadline)
                );
                // TargetLabel already renders the foreground process in the
                // primary label column, so only show an explicit live title.
                let title = title
                    .as_ref()
                    .and_then(|reply| session::live_terminal_title(reply, process.as_ref()))
                    .map_or_else(String::new, |title| clean_truncated(title, 64));
                let status = status.as_ref().and_then(status_summary);
                let process = process.as_ref().and_then(session::process_name);
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

fn custom_window_label(label: &str) -> Option<String> {
    let clean = clean_one_line(label);
    if clean.is_empty() || session::is_default_window_label(&clean) {
        None
    } else {
        Some(clean)
    }
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

struct TargetSpec<'a> {
    session_index: usize,
    session_id: &'a str,
    window_id: &'a str,
    window_number: usize,
    window_label: Option<String>,
    window_block_count: usize,
    block_id: &'a str,
    block_number: usize,
    block_label: Option<String>,
    block_raw_label: String,
    prefix: String,
    fallback: String,
}

impl Target {
    fn from_spec(spec: TargetSpec<'_>) -> Self {
        let label_parts = TargetLabel {
            prefix: spec.prefix,
            window: spec.window_label.clone(),
            block: spec.block_label.clone(),
            fallback: spec.fallback,
        };
        let label = label_parts.format(None);
        Self {
            server_index: 0,
            session_index: spec.session_index,
            window_id: spec.window_id.to_owned(),
            window_number: spec.window_number,
            window_label: spec.window_label,
            window_block_count: spec.window_block_count,
            block_id: spec.block_id.to_owned(),
            block_number: spec.block_number,
            block_label: spec.block_label,
            block_raw_label: spec.block_raw_label,
            process: None,
            label,
            label_parts,
            title: String::new(),
            status: None,
            session_id: spec.session_id.to_owned(),
        }
    }

    pub(super) fn key(&self) -> TargetKey {
        TargetKey {
            session_id: self.session_id.clone(),
            window_id: self.window_id.clone(),
            block_id: self.block_id.clone(),
        }
    }
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
                targets.push(Target::from_spec(TargetSpec {
                    session_index,
                    session_id,
                    window_id: &window.id,
                    window_number: number,
                    window_label: window_label.clone(),
                    window_block_count: block_count,
                    block_id: &block.id,
                    block_number: split_index + 1,
                    block_label: custom_block_label(&block.label),
                    block_raw_label: clean_one_line(&block.label),
                    prefix: format!("{session} / {number}.{}", split_index + 1),
                    fallback: label_or_id(&block.label, &block.id),
                }));
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
            targets.push(Target::from_spec(TargetSpec {
                session_index,
                session_id,
                window_id: &window.id,
                window_number: number,
                window_label,
                window_block_count: 1,
                block_id,
                block_number: 1,
                block_label: custom_block_label(block_label_str),
                block_raw_label,
                prefix: format!("{session} / {number}"),
                fallback,
            }));
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
            let (visible, truncated) = truncate_to_columns(part.text, part.limit);
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
        let (visible, truncated) = truncate_to_columns(tag, columns);
        if !visible.is_empty() {
            spans.push(StyledSpan {
                role: StyleRole::Title,
                text: visible,
                search_offset: None,
            });
        }
        if truncated {
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

    let target_width = target.width();
    if !detail.is_empty() && target_width + 1 + detail.width() <= remaining {
        push_label_spans(&mut spans, target, 0, false);
        spans.push(StyledSpan {
            role: StyleRole::Title,
            text: format!(" {detail}"),
            search_offset: None,
        });
    } else if !detail.is_empty() && target_width + 1 + ellipsis_width < remaining {
        push_label_spans(&mut spans, target, 0, false);
        let (visible, _) = truncate_to_columns(detail, remaining - target_width - 1);
        if !visible.is_empty() {
            spans.push(StyledSpan {
                role: StyleRole::Title,
                text: format!(" {visible}…"),
                search_offset: None,
            });
        }
    } else {
        let (visible, truncated) = truncate_to_columns(target, remaining);
        push_label_spans(&mut spans, &visible, 0, truncated);
    }
    spans
}

fn styled_label(text: &str, columns: usize) -> Vec<StyledSpan> {
    if columns == 0 || text.is_empty() {
        return Vec::new();
    }
    let mut spans = Vec::new();
    let (visible, truncated) = truncate_to_columns(text, columns);
    push_label_spans(&mut spans, &visible, 0, truncated);
    spans
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
            LocalDiscovery::Optional,
            async |_| Ok(None),
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
            LocalDiscovery::Optional,
            async |_| Ok(None),
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
        assert_eq!(loaded.local_discovery, LocalDiscovery::None);
        assert!(loaded.has_configured_sources);
        assert_eq!(
            loaded.servers,
            vec![Server {
                name: "mac".to_owned(),
                address: "https://mac.tail.ts.net".parse().unwrap(),
            }]
        );

        // Explicit `local` without a saved `local` entry requires probing the local server directly.
        let loaded = load_servers_with(
            &ServerConfig::Explicit("local".to_owned()),
            &config,
            fake_local,
        )
        .await
        .unwrap();
        assert_eq!(loaded.local_discovery, LocalDiscovery::Required);
        assert!(loaded.has_configured_sources);
        assert!(loaded.servers.is_empty());

        // When no local server is running, `-S local` names the local server instead of "no reachable servers".
        let local_missing = discover_all(
            loaded.servers,
            loaded.local_discovery,
            async |_| Ok(None),
            Instant::now() + DISCOVERY_TIME,
        )
        .await;
        assert!(local_missing.servers.is_empty());
        assert_eq!(
            local_missing.unreachable_error(),
            "local: server is not running"
        );

        // A conflicting alias cannot redirect -S local.
        let mut custom_local_cfg = config::Config::default();
        custom_local_cfg
            .servers
            .insert("local".to_owned(), "http://127.0.0.1:9999".to_owned());
        let loaded = load_servers_with(
            &ServerConfig::Explicit("local".to_owned()),
            &custom_local_cfg,
            fake_local,
        )
        .await
        .unwrap();
        assert_eq!(loaded.local_discovery, LocalDiscovery::Required);
        assert!(loaded.servers.is_empty());

        // REX_SERVER set to a saved alias deduplicates against saved servers.
        let loaded = load_servers_with(&ServerConfig::Env("mac".to_owned()), &config, fake_local)
            .await
            .unwrap();
        assert_eq!(loaded.local_discovery, LocalDiscovery::None);
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
        assert_eq!(loaded.local_discovery, LocalDiscovery::None);
        assert!(loaded.has_configured_sources);
        assert_eq!(
            loaded
                .servers
                .iter()
                .map(|server| server.name.as_str())
                .collect::<Vec<_>>(),
            vec!["REX_SERVER", "mac", "office"]
        );

        // REX_SERVER=local (case-insensitive) defers local probing to discover_all.
        let panic_local = || async {
            panic!("local probe must not run synchronously in load_servers_with");
            #[allow(unreachable_code)]
            "http://127.0.0.1:7297".parse::<ServerAddress>().unwrap()
        };
        let loaded =
            load_servers_with(&ServerConfig::Env("LOCAL".to_owned()), &config, panic_local)
                .await
                .unwrap();
        assert_eq!(loaded.local_discovery, LocalDiscovery::Required);
        assert!(loaded.has_configured_sources);
        assert_eq!(
            loaded
                .servers
                .iter()
                .map(|server| server.name.as_str())
                .collect::<Vec<_>>(),
            vec!["mac", "office"]
        );

        // A saved server named `local` cannot override the built-in local alias for REX_SERVER=local.
        let mut with_saved_local = config::Config::default();
        with_saved_local
            .servers
            .insert("local".to_owned(), "http://127.0.0.1:9999".to_owned());
        with_saved_local
            .servers
            .insert("mac".to_owned(), "https://mac.tail.ts.net".to_owned());
        with_saved_local
            .servers
            .insert("office".to_owned(), "https://office.example".to_owned());
        let loaded = load_servers_with(
            &ServerConfig::Env("local".to_owned()),
            &with_saved_local,
            panic_local,
        )
        .await
        .unwrap();
        assert_eq!(loaded.local_discovery, LocalDiscovery::Required);
        assert!(loaded.has_configured_sources);
        assert_eq!(
            loaded
                .servers
                .iter()
                .map(|server| server.name.as_str())
                .collect::<Vec<_>>(),
            vec!["mac", "office"]
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
        assert_eq!(loaded.local_discovery, LocalDiscovery::Optional);
        assert!(!loaded.has_configured_sources);
        assert!(loaded.servers.is_empty());

        let outcome = discover_all(
            loaded.servers,
            loaded.local_discovery,
            async |_| Ok(None),
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
            loaded.local_discovery,
            async |_| Ok(None),
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
        assert_eq!(loaded.local_discovery, LocalDiscovery::None);
        assert!(loaded.servers.is_empty());
        let outcome = discover_all(
            loaded.servers,
            loaded.local_discovery,
            async |_| Ok(None),
            Instant::now() + DISCOVERY_TIME,
        )
        .await;
        assert!(!outcome.has_no_sources(loaded.has_configured_sources));

        // 4. Local probe fails with a connection error -> source existed.
        let outcome = discover_all(
            Vec::new(),
            LocalDiscovery::Optional,
            async |_| Err(anyhow!("local: connection refused")),
            Instant::now() + DISCOVERY_TIME,
        )
        .await;
        assert!(outcome.servers.is_empty());
        assert_eq!(outcome.warnings.len(), 1);
        assert!(!outcome.has_no_sources(false));

        // 5. Local probe times out -> do not mask timeout as no sources.
        let outcome = discover_all(
            Vec::new(),
            LocalDiscovery::Optional,
            async |_| std::future::pending().await,
            Instant::now() + Duration::from_millis(10),
        )
        .await;
        assert!(outcome.servers.is_empty());
        assert_eq!(outcome.warnings.len(), 1);
        assert!(!outcome.has_no_sources(false));

        // 6. Explicit -S against an unreachable server -> reports unreachable error, not no-server error.
        let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_url = format!("http://{}", dead_listener.local_addr().unwrap());
        drop(dead_listener);
        let loaded =
            load_servers_with(&ServerConfig::Explicit(dead_url), &empty_config, fake_local)
                .await
                .unwrap();
        assert!(loaded.has_configured_sources);
        assert_eq!(loaded.local_discovery, LocalDiscovery::None);
        let outcome = discover_all(
            loaded.servers,
            loaded.local_discovery,
            async |_| Ok(None),
            Instant::now() + DISCOVERY_TIME,
        )
        .await;
        assert!(outcome.servers.is_empty());
        assert_eq!(outcome.warnings.len(), 1);
        assert!(!outcome.has_no_sources(loaded.has_configured_sources));

        // 7. REX_SERVER=local with absent/unreachable local server -> warning & configured source, not no-server error.
        let loaded = load_servers_with(
            &ServerConfig::Env("local".to_owned()),
            &empty_config,
            fake_local,
        )
        .await
        .unwrap();
        assert_eq!(loaded.local_discovery, LocalDiscovery::Required);
        assert!(loaded.has_configured_sources);
        let outcome = discover_all(
            loaded.servers,
            loaded.local_discovery,
            async |_| Ok(None),
            Instant::now() + DISCOVERY_TIME,
        )
        .await;
        assert!(outcome.servers.is_empty());
        assert_eq!(outcome.warnings.len(), 1);
        assert_eq!(outcome.unreachable_error(), "local: server is not running");
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
        let (mut ctrl, _events) = Control::connect(&server.address, None).await.unwrap();
        let initial = discover_with_control(&mut ctrl, &server, Instant::now() + DISCOVERY_TIME)
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
                target: &ManageTarget {
                    server_index: 0,
                    session_id: "session:1".to_owned(),
                    scope: ManageScope::Session,
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
                target: &ManageTarget {
                    server_index: 0,
                    session_id: "session:1".to_owned(),
                    scope: ManageScope::Window("window:1".to_owned()),
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
                target: &ManageTarget {
                    server_index: 0,
                    session_id: "session:1".to_owned(),
                    scope: ManageScope::Block("block:1".to_owned()),
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
                target: &ManageTarget {
                    server_index: 0,
                    session_id: "session:1".to_owned(),
                    scope: ManageScope::Block("block:2".to_owned()),
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
                target: &ManageTarget {
                    server_index: 0,
                    session_id: "session:1".to_owned(),
                    scope: ManageScope::Window("window:1".to_owned()),
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
                target: &ManageTarget {
                    server_index: 0,
                    session_id: "session:1".to_owned(),
                    scope: ManageScope::Session,
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

    #[test]
    fn discovery_warning_feedback_formats_single_and_multiple_warnings() {
        assert_eq!(discovery_warning_feedback(&[]), None);
        assert_eq!(
            discovery_warning_feedback(&["dead: connection refused".to_owned()]),
            Some(prompt::Feedback {
                text: "dead: connection refused".to_owned(),
                is_error: true,
            })
        );
        assert_eq!(
            discovery_warning_feedback(&[
                "dead: connection refused".to_owned(),
                "slow: discovery timed out".to_owned(),
            ]),
            Some(prompt::Feedback {
                text: "dead: connection refused (and 1 more server warning)".to_owned(),
                is_error: true,
            })
        );
        assert_eq!(
            discovery_warning_feedback(&[
                "dead: connection refused".to_owned(),
                "slow: discovery timed out".to_owned(),
                "bad: invalid token".to_owned(),
            ]),
            Some(prompt::Feedback {
                text: "dead: connection refused (and 2 more server warnings)".to_owned(),
                is_error: true,
            })
        );
    }

    #[tokio::test]
    async fn discover_all_runs_required_local_in_parallel_and_deduplicates() {
        use futures_util::SinkExt;
        use tokio::net::TcpListener;
        use tokio_tungstenite::accept_hdr_async;
        use tokio_tungstenite::tungstenite::Message;
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
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
                        let payload = match req["method"].as_str().unwrap() {
                            "session.attach_all" => json!({"sessions": []}),
                            other => panic!("unexpected method {other}"),
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

        let saved_url = format!("http://{live_addr}");

        // Hanging local probe still allows saved servers to succeed under deadline.
        let outcome = discover_all(
            vec![Server {
                name: "office".to_owned(),
                address: saved_url.parse().unwrap(),
            }],
            LocalDiscovery::Required,
            async |_| std::future::pending().await,
            Instant::now() + Duration::from_millis(50),
        )
        .await;
        assert_eq!(outcome.servers.len(), 1);
        assert_eq!(outcome.servers[0].name, "office");
        assert_eq!(outcome.warnings, vec!["local server detection timed out"]);

        // Matching saved server address deduplicates cleanly.
        let saved_addr: ServerAddress = saved_url.parse().unwrap();
        let outcome = discover_all(
            vec![Server {
                name: "office".to_owned(),
                address: saved_url.parse().unwrap(),
            }],
            LocalDiscovery::Required,
            async move |_| {
                let (ctrl, _events) = Control::connect(&saved_addr, None).await?;
                Ok(Some((saved_addr, ctrl)))
            },
            Instant::now() + DISCOVERY_TIME,
        )
        .await;
        assert_eq!(outcome.servers.len(), 1);
        assert_eq!(outcome.servers[0].name, "office");
        assert!(outcome.warnings.is_empty());
    }

    #[tokio::test]
    async fn apply_manage_refreshes_on_404_status_and_skips_500() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use futures_util::SinkExt;
        use tokio::net::TcpListener;
        use tokio_tungstenite::accept_hdr_async;
        use tokio_tungstenite::tungstenite::Message;
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

        let status_to_return = Arc::new(AtomicUsize::new(404));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let status_flag = Arc::clone(&status_to_return);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let status_flag = Arc::clone(&status_flag);
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
                        let msg = match req["method"].as_str().unwrap() {
                            "session.attach" => json!({
                                "type": "response",
                                "id": id,
                                "seq": 0,
                                "payload": {"session_id": "session:1"}
                            }),
                            "session.close_window" => {
                                let status = status_flag.load(Ordering::Relaxed);
                                json!({
                                    "type": "response",
                                    "id": id,
                                    "seq": 0,
                                    "error": {
                                        "code": "custom_code",
                                        "message": "gone",
                                        "status": status
                                    }
                                })
                            }
                            "session.attach_all" => json!({
                                "type": "response",
                                "id": id,
                                "seq": 0,
                                "payload": {"sessions": []}
                            }),
                            other => panic!("unexpected method {other}"),
                        };
                        ws.send(Message::text(msg.to_string())).await.unwrap();
                    }
                });
            }
        });

        let server = Server {
            name: "office".to_owned(),
            address: format!("http://{addr}").parse().unwrap(),
        };
        let target = ManageTarget {
            server_index: 0,
            session_id: "session:1".to_owned(),
            scope: ManageScope::Window("window:1".to_owned()),
        };

        let applied_404 = apply_manage(
            &server,
            ManageOp::Kill { target: &target },
            Instant::now() + DISCOVERY_TIME,
            DISCOVERY_TIME,
        )
        .await;
        assert!(applied_404.result.is_err());
        assert!(matches!(applied_404.refreshed, Some(Ok(_))));

        status_to_return.store(500, Ordering::Relaxed);
        let applied_500 = apply_manage(
            &server,
            ManageOp::Kill { target: &target },
            Instant::now() + DISCOVERY_TIME,
            DISCOVERY_TIME,
        )
        .await;
        assert!(applied_500.result.is_err());
        assert!(applied_500.refreshed.is_none());
    }

    #[test]
    fn classify_attach_result_handles_detach_double_detach_close_and_errors() {
        assert_eq!(
            classify_attach_result(
                "Attach failed",
                "office".to_owned(),
                Ok(app::AttachExit::Detached {
                    session_id: "session:1".to_owned(),
                    block_id: "block:2".to_owned(),
                    double_detach: true,
                }),
            ),
            PostAttach::Quit
        );

        assert_eq!(
            classify_attach_result(
                "Attach failed",
                "office".to_owned(),
                Ok(app::AttachExit::Detached {
                    session_id: "session:1".to_owned(),
                    block_id: "block:2".to_owned(),
                    double_detach: false,
                }),
            ),
            PostAttach::Return {
                focus: Some(prompt::FocusTarget {
                    server_name: "office".to_owned(),
                    session_id: "session:1".to_owned(),
                    block_id: "block:2".to_owned(),
                }),
                feedback: None,
            }
        );

        assert_eq!(
            classify_attach_result(
                "Create session failed",
                "local".to_owned(),
                Ok(app::AttachExit::BlockClosed),
            ),
            PostAttach::Return {
                focus: None,
                feedback: Some(prompt::Feedback {
                    text: "The block closed".to_owned(),
                    is_error: false,
                }),
            }
        );

        assert_eq!(
            classify_attach_result(
                "Create window failed",
                "local".to_owned(),
                Ok(app::AttachExit::SessionClosed),
            ),
            PostAttach::Return {
                focus: None,
                feedback: Some(prompt::Feedback {
                    text: "The session closed".to_owned(),
                    is_error: false,
                }),
            }
        );

        assert_eq!(
            classify_attach_result(
                "Create window failed",
                "office".to_owned(),
                Err(anyhow!("connection refused")),
            ),
            PostAttach::Return {
                focus: None,
                feedback: Some(prompt::Feedback {
                    text: "Create window failed: connection refused".to_owned(),
                    is_error: true,
                }),
            }
        );
    }

    #[test]
    fn apply_refresh_outcome_updates_targets_and_handles_unreachable_servers() {
        let mut outcome = DiscoveryOutcome {
            servers: vec![Server {
                name: "local".to_owned(),
                address: "http://127.0.0.1:7297".parse().unwrap(),
            }],
            sessions: vec![SessionChoice {
                server_index: 0,
                server_name: "local".to_owned(),
                session_id: "session:1".to_owned(),
                label: "work".to_owned(),
            }],
            choices: vec![test_target(
                0,
                0,
                "[local] work / 1 zsh",
                "session:1",
                "block:1",
            )],
            warnings: Vec::new(),
            attempted_any: true,
        };
        let mut state = prompt::PickerState::new(
            outcome.choices.clone(),
            outcome.sessions.clone(),
            vec!["local".to_owned()],
        );
        state.reset_after_attach(
            Some(prompt::FocusTarget {
                server_name: "local".to_owned(),
                session_id: "session:2".to_owned(),
                block_id: "block:2".to_owned(),
            }),
            None,
        );

        // If refresh finds no reachable servers, keep the existing server list and report the error.
        let unreachable = DiscoveryOutcome {
            servers: Vec::new(),
            sessions: Vec::new(),
            choices: Vec::new(),
            warnings: vec!["local: connection refused".to_owned()],
            attempted_any: true,
        };
        apply_refresh_outcome(&mut outcome, &mut state, unreachable);
        assert_eq!(outcome.servers.len(), 1);
        assert_eq!(outcome.choices.len(), 1);

        // A subsequent successful refresh replaces outcome and exposes newly discovered sessions.
        let refreshed = DiscoveryOutcome {
            servers: vec![Server {
                name: "local".to_owned(),
                address: "http://127.0.0.1:7297".parse().unwrap(),
            }],
            sessions: vec![
                SessionChoice {
                    server_index: 0,
                    server_name: "local".to_owned(),
                    session_id: "session:1".to_owned(),
                    label: "work".to_owned(),
                },
                SessionChoice {
                    server_index: 0,
                    server_name: "local".to_owned(),
                    session_id: "session:2".to_owned(),
                    label: "fresh".to_owned(),
                },
            ],
            choices: vec![
                test_target(0, 0, "[local] work / 1 zsh", "session:1", "block:1"),
                test_target(0, 1, "[local] fresh / 1 zsh", "session:2", "block:2"),
            ],
            warnings: Vec::new(),
            attempted_any: true,
        };
        apply_refresh_outcome(&mut outcome, &mut state, refreshed);
        assert_eq!(outcome.choices.len(), 2);
        assert_eq!(outcome.sessions.len(), 2);
    }
}
