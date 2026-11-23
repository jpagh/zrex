use std::io::{IsTerminal, Read, Write};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use serde_json::{Value, json};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;

use crate::config::ServerConfig;
use crate::rex::control::{CALL_TIME, CallTimeout, Control, Events};
use crate::rex::data::{self, Data, StreamClosed};
use crate::rex::proto;
use crate::rex::stream::{self, Filter};
use crate::rex::{BlockRef, ServerAddress, format_timeout};
use crate::session;

const DATA_REF: &str = "terminal";
const MAX_BLOB_BYTES: usize = 983_040;
/// Cap total reassembled blob/clipboard size so a misbehaving server cannot
/// cause unbounded memory growth.
const MAX_TOTAL_BLOB_BYTES: usize = 16 * 1024 * 1024;
const BLOB_READ_TIME: Duration = CALL_TIME;
/// Cap each `com.superlogical.terminal.write` request so huge pastes stay well
/// within WebSocket frame limits while normal input goes out in one call.
const MAX_WRITE_BYTES: usize = 64 * 1024;
const PROBE_EVERY: Duration = Duration::from_secs(10);
const PROBE_TIME: Duration = Duration::from_secs(5);
const DETACH_TIME: Duration = Duration::from_secs(1);
const RETRY_FIRST: Duration = Duration::from_millis(250);
const RETRY_MAX: Duration = Duration::from_secs(5);
const THEME_PROBE_TIMEOUT: Duration = Duration::from_millis(100);
const TITLE_QUERY_TIMEOUT: Duration = Duration::from_millis(250);
/// An unterminated local reply grows no larger than this before zrex stops
/// holding it and forwards the bytes as input. The longest reply a terminal
/// sends is a 256-color palette entry at 29 bytes.
const MAX_HELD_REPLY: usize = 64;
/// A terminal answers a query in one burst, so a fragment held this long was
/// typing after all, and a reply this old is no longer a sign that more are
/// coming.
const REPLY_HOLD: Duration = Duration::from_millis(50);
/// DECSET 2031 asks the host terminal to report light and dark switches, which
/// the block's theme follows while attached.
const WATCH_SCHEME: &[u8] = b"\x1b[?2031h";

const RESET_COLORS: &[u8] =
    b"\x1b]104\x1b\\\x1b]110\x1b\\\x1b]111\x1b\\\x1b]112\x1b\\\x1b]104\x07\x1b]110\x07\x1b]111\x07\x1b]112\x07";

/// Restore host terminal state on exit in case a program inside the block
/// enabled alternate screen, mouse tracking, Kitty keyboard, color-scheme
/// reporting, or custom palette colors.
const RESET_MODES: &[u8] = concat!(
    "\x1b[?2026l",
    "\x1b[<u",
    "\x1b[>4;0m",
    "\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1015l",
    "\x1b[?1004l",
    "\x1b[?2004l",
    "\x1b[?2031l",
    "\x1b[?1l\x1b>",
    "\x1b[?1049l",
    "\x1b[r",
    "\x1b]104\x1b\\\x1b]110\x1b\\\x1b]111\x1b\\\x1b]112\x1b\\",
    "\x1b]104\x07\x1b]110\x07\x1b]111\x07\x1b]112\x07",
    "\x1b[23;0t",
    "\x1b[?25h",
    "\x1b[0m\r\n",
)
.as_bytes();

/// Forwarded to `com.superlogical.terminal.set_theme` when taking block
/// ownership so server-side terminal queries report the host terminal's theme
/// instead of the server's built-in dark default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Theme {
    foreground: Option<String>,
    background: Option<String>,
    cursor: Option<String>,
    palette: Vec<String>,
    scheme: Option<String>,
}

impl Theme {
    fn is_empty(&self) -> bool {
        self.foreground.is_none()
            && self.background.is_none()
            && self.cursor.is_none()
            && self.palette.is_empty()
            && self.scheme.is_none()
    }

    fn to_json(&self) -> Value {
        let mut args = json!({});
        if let Some(fg) = &self.foreground {
            args["foreground"] = json!(fg);
        }
        if let Some(bg) = &self.background {
            args["background"] = json!(bg);
        }
        if let Some(cursor) = &self.cursor {
            args["cursor"] = json!(cursor);
        }
        if !self.palette.is_empty() {
            args["palette"] = json!(self.palette);
        }
        if let Some(scheme) = &self.scheme {
            args["scheme"] = json!(scheme);
        }
        args
    }
}

pub fn has_terminal() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

pub fn ensure_terminal() -> Result<()> {
    if !has_terminal() {
        bail!("zrex needs a terminal to attach to a session");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachExit {
    Detached {
        session_id: String,
        block_id: String,
        /// True when a second detach sequence was already read right behind the
        /// first detach sequence (fast double-detach).
        double_detach: bool,
    },
    BlockClosed {
        session_id: String,
        block_id: String,
    },
    SessionClosed {
        session_id: String,
    },
}

impl AttachExit {
    pub fn closed_message(&self) -> Option<&'static str> {
        match self {
            Self::BlockClosed { .. } => Some("the block closed"),
            Self::SessionClosed { .. } => Some("the session closed"),
            Self::Detached { .. } => None,
        }
    }

    fn cli_message(&self) -> String {
        match self {
            Self::Detached { session_id, .. } => format!("detached from {session_id}"),
            other => other.closed_message().unwrap_or_default().to_owned(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TerminalMode {
    RestoreOnLeave,
    KeepRawOnLeave,
}

pub async fn attach(
    server_config: &ServerConfig,
    target: Option<String>,
    window: Option<String>,
    block: Option<String>,
) -> Result<()> {
    ensure_terminal()?;
    let (server, mut ctrl, events) = server_config.connect().await?;
    let session_id = match target.as_deref() {
        Some(target) => session::find_or_create(&mut ctrl, target).await?,
        None => session::pick(&mut ctrl, None).await?,
    };
    let (window, block) = match window.as_deref() {
        Some(selector) => {
            session::attach(&mut ctrl, &session_id).await?;
            let (win_id, blk) =
                session::ensure_window(&mut ctrl, &session_id, selector, block.as_deref()).await?;
            (Some(win_id), blk)
        }
        None => (None, block),
    };
    let exit = attach_block(
        &server,
        ctrl,
        events,
        &session_id,
        BlockSelection::Selectors(window.as_deref(), block.as_deref()),
        TerminalMode::RestoreOnLeave,
    )
    .await?;
    println!("{}", exit.cli_message());
    Ok(())
}

/// Picker targets are a snapshot of existing IDs, never creation selectors.
pub async fn attach_existing(
    server: &ServerAddress,
    session_id: &str,
    block_id: &str,
) -> Result<AttachExit> {
    ensure_terminal()?;
    let (mut ctrl, events) = Control::connect(server, None).await?;
    session::attach(&mut ctrl, session_id).await?;
    attach_block(
        server,
        ctrl,
        events,
        session_id,
        BlockSelection::Exact(block_id),
        TerminalMode::KeepRawOnLeave,
    )
    .await
}

pub async fn attach_new_session(server: &ServerAddress, label: Option<&str>) -> Result<AttachExit> {
    ensure_terminal()?;
    let (mut ctrl, events) = Control::connect(server, None).await?;
    let session_id = session::create(&mut ctrl, label).await?;
    attach_block(
        server,
        ctrl,
        events,
        &session_id,
        BlockSelection::Selectors(None, None),
        TerminalMode::KeepRawOnLeave,
    )
    .await
}

pub async fn attach_new_window(
    server: &ServerAddress,
    session_id: &str,
    label: Option<&str>,
) -> Result<AttachExit> {
    ensure_terminal()?;
    let (mut ctrl, events) = Control::connect(server, None).await?;
    session::attach(&mut ctrl, session_id).await?;
    let window_id = session::new_window(&mut ctrl, session_id, label).await?;
    attach_block(
        server,
        ctrl,
        events,
        session_id,
        BlockSelection::Selectors(Some(&window_id), None),
        TerminalMode::KeepRawOnLeave,
    )
    .await
}

#[derive(Clone, Copy)]
enum BlockSelection<'a> {
    Selectors(Option<&'a str>, Option<&'a str>),
    Exact(&'a str),
}

async fn attach_block(
    server: &ServerAddress,
    mut ctrl: Control,
    mut events: Events,
    session_id: &str,
    selection: BlockSelection<'_>,
    terminal_mode: TerminalMode,
) -> Result<AttachExit> {
    let size = crossterm::terminal::size()?;
    let mut guard = Screen::enter(terminal_mode)?;
    let (theme, probe_tail) = guard.probe_theme();
    let mut attached =
        Attached::start(&mut ctrl, session_id, server, selection, size, theme).await?;
    // Replies the probe deadline cut off arrive after it returns, so the reader
    // that takes over stdin starts out holding the fragment it left.
    attached.replies.hold(probe_tail);

    let mut input = InputReader::spawn()?;
    let mut winch = signal(SignalKind::window_change())?;
    let mut probe = tokio::time::interval(PROBE_EVERY);
    probe.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    probe.reset();
    let mut token = ctrl.reconnect_token.clone();

    loop {
        let mut lost: Option<anyhow::Error> = None;
        tokio::select! {
            chunk = attached.data.next_chunk() => {
                match chunk {
                    Some(Ok(bytes)) => {
                        if let Err(error) = attached.feed(&bytes, &mut ctrl).await {
                            lost = Some(error);
                        } else {
                            while let Some(next) = attached.data.try_next_chunk() {
                                match next {
                                    Ok(more) => {
                                        if let Err(error) = attached.feed(&more, &mut ctrl).await {
                                            lost = Some(error);
                                            break;
                                        }
                                    }
                                    Err(error) if closed_block(&error) => {
                                        attached.flush(guard.out())?;
                                        return finish_ending(
                                            &mut input,
                                            &mut guard,
                                            attached,
                                            Ending::Block,
                                        );
                                    }
                                    Err(error) => {
                                        lost = Some(stream_lost(error));
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Some(Err(error)) if closed_block(&error) => {
                        return finish_ending(&mut input, &mut guard, attached, Ending::Block);
                    }
                    Some(Err(error)) => lost = Some(stream_lost(error)),
                    None => lost = Some(data_ended()),
                }
            }
            message = events.recv() => {
                match message {
                    Some((name, payload)) => {
                        match attached.event(&name, &payload, &mut ctrl).await {
                            Ok(Some(ending)) => {
                                return finish_ending(&mut input, &mut guard, attached, ending);
                            }
                            Ok(None) => {}
                            Err(error) => lost = Some(error),
                        }
                    }
                    None => lost = Some(anyhow!("the control connection ended")),
                }
            }
            Some(bytes) = input.recv() => {
                match attached.burst(&bytes, &mut input, &mut ctrl).await {
                    Ok(Flow::Detach { double }) => {
                        return finish_detach(
                            &mut ctrl,
                            &mut input,
                            &mut guard,
                            attached,
                            double,
                            DetachMode::Graceful,
                        )
                        .await;
                    }
                    Ok(Flow::Continue) => {}
                    Err(error) => lost = Some(error),
                }
            }
            // Rex runs `com.superlogical.terminal.write` calls concurrently, so
            // wait for each write to be queued on the server before sending the
            // next coalesced batch.
            result = finish_write(&mut attached.write_inflight) => {
                match result {
                    Ok(_) => {
                        if let Err(error) = attached.pump_write(&mut ctrl) {
                            lost = Some(error);
                        }
                    }
                    Err(error) if write_target_gone(&error) => {
                        // The block or session already closed on the server;
                        // wait for the close event or data stream end instead
                        // of failing the attach loop with an error.
                        attached.write_queue.clear();
                    }
                    Err(error) => lost = Some(error),
                }
            }
            // A fragment the host stopped sending was typing after all.
            _ = stalled(attached.replies.due()) => {
                // Another arm can hold the loop long enough for the host's
                // continuation to queue up behind it, so take that first.
                if input.is_empty() {
                    if let Err(error) = attached.flush_held(&mut ctrl).await {
                        lost = Some(error);
                    }
                } else {
                    attached.replies.defer();
                }
            }
            _ = winch.recv() => {
                if let Ok((cols, rows)) = crossterm::terminal::size()
                    && let Err(error) = attached.resize(cols, rows, &mut ctrl).await
                {
                    lost = Some(error);
                }
            }
            _ = probe.tick() => {
                // A socket reports a dead network only when something uses
                // it, so use it.
                if let Err(error) = ctrl
                    .call_with_timeout("server.version", Value::Null, PROBE_TIME)
                    .await
                {
                    lost = Some(error);
                }
            }
        }

        if lost.is_none() && attached.theme_dirty {
            match attached
                .refresh_theme(guard.out(), &mut input, &mut ctrl)
                .await
            {
                Ok(Flow::Continue) => {}
                Ok(Flow::Detach { double }) => {
                    return finish_detach(
                        &mut ctrl,
                        &mut input,
                        &mut guard,
                        attached,
                        double,
                        DetachMode::Graceful,
                    )
                    .await;
                }
                Err(error) => lost = Some(error),
            }
        }

        if let Some(error) = lost {
            if !transient(&ctrl, &error) {
                return Err(error);
            }
            match recover(
                &mut token,
                &mut ctrl,
                &mut events,
                &mut attached,
                &mut input,
            )
            .await?
            {
                Recovered::Live => {}
                Recovered::Detach { double } => {
                    return finish_detach(
                        &mut ctrl,
                        &mut input,
                        &mut guard,
                        attached,
                        double,
                        DetachMode::Immediate,
                    )
                    .await;
                }
                Recovered::Ended(ending) => {
                    return finish_ending(&mut input, &mut guard, attached, ending);
                }
            }
        }

        attached.flush(guard.out())?;
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DetachMode {
    /// Connected: drain queued and in-flight keystrokes before `session.detach`.
    Graceful,
    /// Interrupted during reconnect: skip draining writes and just send `session.detach`.
    Immediate,
}

fn finish_ending(
    input: &mut InputReader,
    guard: &mut Screen,
    attached: Attached<'_>,
    ending: Ending,
) -> Result<AttachExit> {
    input.stop();
    guard.leave()?;
    Ok(ending.into_exit(attached.session_id, attached.block_id))
}

async fn finish_detach(
    ctrl: &mut Control,
    input: &mut InputReader,
    guard: &mut Screen,
    mut attached: Attached<'_>,
    mut double_detach: bool,
    mode: DetachMode,
) -> Result<AttachExit> {
    double_detach |= input.stop_and_drain_detach();
    match mode {
        DetachMode::Graceful => detach(ctrl, &mut attached).await,
        DetachMode::Immediate => {
            detach_session(
                ctrl,
                &attached.session_id,
                tokio::time::Instant::now() + DETACH_TIME,
            )
            .await;
        }
    }
    guard.leave()?;
    Ok(AttachExit::Detached {
        session_id: attached.session_id,
        block_id: attached.block_id,
        double_detach,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flow {
    Continue,
    Detach { double: bool },
}

impl Flow {
    fn detach_after(tail: &[u8]) -> Self {
        Self::Detach {
            double: contains_detach(tail),
        }
    }
}

enum Ending {
    Block,
    Session,
}

impl Ending {
    fn into_exit(self, session_id: String, block_id: String) -> AttachExit {
        match self {
            Ending::Block => AttachExit::BlockClosed {
                session_id,
                block_id,
            },
            Ending::Session => AttachExit::SessionClosed { session_id },
        }
    }
}

struct InflightWrite {
    rx: tokio::sync::oneshot::Receiver<Result<Value>>,
    deadline: tokio::time::Instant,
}

struct Attached<'a> {
    server: &'a ServerAddress,
    session_id: String,
    block_id: String,
    client_id: String,
    size: (u16, u16),
    theme: Theme,
    fallback_title: Option<String>,
    data: Data,
    filter: Filter,
    pending: Vec<u8>,
    out: Vec<u8>,
    input_buf: Vec<u8>,
    write_queue: String,
    write_inflight: Option<InflightWrite>,
    replies: Replies,
    primed: bool,
    theme_dirty: bool,
    owns: bool,
}

impl<'a> Attached<'a> {
    async fn start(
        ctrl: &mut Control,
        session_id: &str,
        server: &'a ServerAddress,
        selection: BlockSelection<'_>,
        (cols, rows): (u16, u16),
        theme: Theme,
    ) -> Result<Self> {
        let bootstrap = ctrl
            .call(
                "session.bootstrap",
                json!({
                    "event_scope": "all",
                    "preferred_session_id": session_id,
                }),
            )
            .await?;
        let client_id = bootstrap
            .get("client_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("bootstrap returned no client_id"))?
            .to_owned();
        let view = bootstrap
            .get("selected_session")
            .and_then(|selected| selected.get("view"))
            .cloned()
            .ok_or_else(|| anyhow!("bootstrap attached to no session"))?;
        let block_id = match selection {
            BlockSelection::Exact(id) if session::has_block(&view, id) => id.to_owned(),
            BlockSelection::Exact(id) => bail!("the selected block {id} is no longer available"),
            BlockSelection::Selectors(window, block) => session::block_of(&view, window, block)
                .ok_or_else(|| match (window, block) {
                    (_, Some(blk)) => anyhow!("the window has no block {blk}"),
                    (Some(win), None) => anyhow!("the session has no window {win}"),
                    (None, None) => anyhow!("the session's active window shows no block"),
                })?,
        };
        let fallback_title = session::fallback_title_for(&bootstrap, &view, &block_id);

        let block = BlockRef::new(session_id, &block_id);
        start_take(ctrl, block)?.finish().await?;
        let ticket_call = start_ticket(ctrl, block)?;
        publish(ctrl, block, (cols, rows), &theme, Push::Both).await?;
        let ticket = parse_ticket(&ticket_call.finish().await?)?;
        let data = Data::open(server, &ticket).await?;
        let filter = Filter::new(data.nonce);
        let attached = Self {
            server,
            session_id: session_id.to_owned(),
            block_id,
            client_id,
            size: (cols, rows),
            theme,
            fallback_title,
            data,
            filter,
            pending: Vec::new(),
            out: Vec::new(),
            input_buf: Vec::new(),
            write_queue: String::new(),
            write_inflight: None,
            replies: Replies::default(),
            primed: false,
            theme_dirty: false,
            owns: true,
        };
        attached.focus(ctrl, "in")?;
        Ok(attached)
    }

    fn block(&self) -> BlockRef<'_> {
        BlockRef::new(&self.session_id, &self.block_id)
    }

    async fn feed(&mut self, bytes: &[u8], ctrl: &mut Control) -> Result<()> {
        if self.primed {
            let filtered = self.filter.push(bytes);
            self.out.extend_from_slice(&filtered);
            return Ok(());
        }
        self.pending.extend_from_slice(bytes);
        let Some(len) = stream::snapshot_len(&self.pending)? else {
            return Ok(());
        };
        let _ = self.filter.push(&self.pending[len..]);
        self.pending.clear();
        self.prime(ctrl).await
    }

    async fn prime(&mut self, ctrl: &mut Control) -> Result<()> {
        let block = self.block();
        let title_rx = session::start_terminal_title(ctrl, block);
        let process_rx = session::start_terminal_process(ctrl, block);
        let screen = format_vt(ctrl, block).await?;
        let deadline = tokio::time::Instant::now() + TITLE_QUERY_TIMEOUT;
        let (title_reply, process_reply) = tokio::join!(
            session::optional_reply(title_rx, deadline),
            session::optional_reply(process_rx, deadline),
        );
        let title = session::resolved_terminal_title(
            title_reply.as_ref(),
            process_reply.as_ref(),
            Some(&screen),
        )
        .or_else(|| self.fallback_title.clone());
        self.out.extend_from_slice(b"\x1b[2J\x1b[H");
        self.out.extend_from_slice(&screen);
        self.out.extend_from_slice(&stream::format_osc_title(
            b'0',
            title.as_deref().unwrap_or(""),
            b"\x07",
        ));
        self.primed = true;
        Ok(())
    }

    fn flush(&mut self, out: &mut impl Write) -> Result<()> {
        if self.out.is_empty() {
            return Ok(());
        }
        out.write_all(&self.out)?;
        out.flush()?;
        self.out.clear();
        Ok(())
    }

    /// Programs in the block ask the server for colors, so the theme zrex gave
    /// the server has to keep up with the host or their answers go stale.
    async fn refresh_theme(
        &mut self,
        out: &mut impl Write,
        input: &mut InputReader,
        ctrl: &mut Control,
    ) -> Result<Flow> {
        self.flush(out)?;
        out.write_all(theme_query().as_bytes())?;
        out.flush()?;
        self.replies.expect_reply();
        let deadline = Instant::now() + THEME_PROBE_TIMEOUT;
        let mut replies = Vec::new();
        while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            let Ok(Some(bytes)) = tokio::time::timeout(remaining, input.recv()).await else {
                break;
            };
            let (before, after_detach) = split_at_detach(&bytes);
            if !before.is_empty() {
                let (found, typed) = self.replies.push(before);
                replies.extend_from_slice(&found);
                if let Flow::Detach { double } = self.accept(&found, &typed) {
                    self.flush_input(ctrl)?;
                    return Ok(Flow::Detach {
                        double: double || after_detach.is_some(),
                    });
                }
            }
            self.flush_input(ctrl)?;
            if let Some(tail) = after_detach {
                return Ok(Flow::detach_after(tail));
            }
            if has_da1_reply(&replies) {
                break;
            }
        }
        self.theme_dirty = false;
        let theme = parse_theme_reply(&replies);
        if theme.is_empty() || theme == self.theme {
            return Ok(Flow::Continue);
        }
        self.theme = theme;
        self.sync(ctrl, Push::Theme).await?;
        Ok(Flow::Continue)
    }

    async fn burst(
        &mut self,
        first: &[u8],
        input: &mut InputReader,
        ctrl: &mut Control,
    ) -> Result<Flow> {
        if let Flow::Detach { mut double } = self.queue_input(first) {
            double |= input.drain_detach();
            self.flush_input(ctrl)?;
            return Ok(Flow::Detach { double });
        }
        while let Some(bytes) = input.try_recv() {
            if let Flow::Detach { mut double } = self.queue_input(&bytes) {
                double |= input.drain_detach();
                self.flush_input(ctrl)?;
                return Ok(Flow::Detach { double });
            }
        }
        let typed = !self.input_buf.is_empty();
        self.flush_input(ctrl)?;
        if typed && !self.owns {
            self.claim(ctrl).await?;
        }
        Ok(Flow::Continue)
    }

    fn queue_input(&mut self, bytes: &[u8]) -> Flow {
        let (before, after_detach) = split_at_detach(bytes);
        if !before.is_empty() {
            let (replies, typed) = self.replies.push(before);
            if let Flow::Detach { double } = self.accept(&replies, &typed) {
                return Flow::Detach {
                    double: double || after_detach.is_some(),
                };
            }
        }
        match after_detach {
            Some(tail) => Flow::detach_after(tail),
            None => Flow::Continue,
        }
    }

    /// Keeps what `Replies::push` classified without parsing the bytes twice.
    fn accept(&mut self, replies: &[u8], typed: &[u8]) -> Flow {
        if reports_scheme(replies) {
            self.theme_dirty = true;
        }
        // The detach key can share a read with a host reply or preceding keys.
        let (before, after_detach) = split_at_detach(typed);
        if !before.is_empty() {
            self.input_buf.extend_from_slice(before);
        }
        match after_detach {
            Some(tail) => Flow::detach_after(tail),
            None => Flow::Continue,
        }
    }

    /// Forwards a fragment the host stopped sending partway through.
    async fn flush_held(&mut self, ctrl: &mut Control) -> Result<()> {
        let held = self.replies.give_up();
        if held.is_empty() {
            return Ok(());
        }
        self.input_buf.extend_from_slice(&held);
        self.flush_input(ctrl)?;
        // Typing this late still makes this client the block's owner.
        if !self.owns {
            self.claim(ctrl).await?;
        }
        Ok(())
    }

    fn flush_input(&mut self, ctrl: &mut Control) -> Result<()> {
        let text = take_utf8(&mut self.input_buf);
        if !text.is_empty() {
            self.write_queue.push_str(&text);
        }
        self.pump_write(ctrl)
    }

    fn pump_write(&mut self, ctrl: &mut Control) -> Result<()> {
        if self.write_inflight.is_some() || self.write_queue.is_empty() {
            return Ok(());
        }
        let chunk = take_write_chunk(&mut self.write_queue, MAX_WRITE_BYTES);
        self.write_inflight = Some(InflightWrite {
            rx: ctrl.start_write(self.block(), &chunk)?,
            deadline: tokio::time::Instant::now() + CALL_TIME,
        });
        Ok(())
    }

    async fn drain_writes(
        &mut self,
        ctrl: &mut Control,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        self.input_buf.extend(self.replies.give_up_typed());
        self.flush_input(ctrl)?;
        loop {
            if self.write_inflight.is_some() {
                match tokio::time::timeout_at(deadline, finish_write(&mut self.write_inflight))
                    .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(_)) | Err(_) => break,
                }
            }
            if self.write_queue.is_empty() {
                break;
            }
            self.pump_write(ctrl)?;
        }
        Ok(())
    }

    async fn resize(&mut self, cols: u16, rows: u16, ctrl: &mut Control) -> Result<()> {
        if cols == 0 || rows == 0 {
            return Ok(());
        }
        self.size = (cols, rows);
        self.sync(ctrl, Push::Size).await
    }

    async fn claim(&mut self, ctrl: &mut Control) -> Result<()> {
        start_take(ctrl, self.block())?.finish().await?;
        self.owns = true;
        self.sync(ctrl, Push::Both).await
    }

    /// The block takes its size and colors from its owner, so this client
    /// publishes its own only while it holds the block and keeps them for the
    /// next claim.
    async fn sync(&mut self, ctrl: &mut Control, push: Push) -> Result<()> {
        if !self.owns {
            return Ok(());
        }
        publish(ctrl, self.block(), self.size, &self.theme, push).await
    }

    fn focus(&self, ctrl: &mut Control, action: &str) -> Result<()> {
        ctrl.post_event(
            self.block(),
            json!({"type": "focus", "payload": {"action": action}}),
        )
    }

    async fn event(
        &mut self,
        event: &str,
        body: &Value,
        ctrl: &mut Control,
    ) -> Result<Option<Ending>> {
        let session = body
            .get("session_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !session.is_empty() && session != self.session_id {
            return Ok(None);
        }
        let block = body
            .get("block_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match event {
            "session_destroyed" => return Ok(Some(Ending::Session)),
            "block_closed" => {
                if block == self.block_id {
                    return Ok(Some(Ending::Block));
                }
            }
            "block_owner_changed" => {
                let owner = body
                    .get("owner")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if block == self.block_id {
                    // Claiming the block back here would make two clients trade
                    // it forever, so a client that lost it waits for the user
                    // to type.
                    let owned = owner == self.client_id;
                    if owned != self.owns {
                        self.owns = owned;
                        self.sync(ctrl, Push::Both).await?;
                    }
                }
            }
            "block_event" if block == self.block_id => {
                self.block_event(body, ctrl).await?;
            }
            _ => {}
        }
        Ok(None)
    }

    async fn block_event(&mut self, body: &Value, ctrl: &mut Control) -> Result<()> {
        let name = body.get("name").and_then(Value::as_str).unwrap_or_default();
        let payload = body.get("payload").cloned().unwrap_or(Value::Null);
        match name {
            "bell" => {
                self.out.push(b'\x07');
            }
            "clipboard_written" => {
                let text = match payload.get("text").and_then(Value::as_str) {
                    Some(text) => text.to_owned(),
                    None => {
                        let id = payload.get("id").and_then(Value::as_i64).unwrap_or(0);
                        clipboard(ctrl, self.block(), id).await?
                    }
                };
                if !text.is_empty() {
                    let encoded = base64::engine::general_purpose::STANDARD.encode(text);
                    self.out
                        .extend_from_slice(format!("\x1b]52;c;{encoded}\x07").as_bytes());
                }
            }
            "desktop_notification" => {
                let title = payload.get("title").and_then(Value::as_str).unwrap_or("");
                let body = payload.get("body").and_then(Value::as_str).unwrap_or("");
                let text = if title.is_empty() {
                    body.to_owned()
                } else {
                    format!("{title}: {body}")
                };
                let clean = text.replace(['\x07', '\x1b'], "");
                if !clean.is_empty() {
                    self.out
                        .extend_from_slice(format!("\x1b]9;{clean}\x07").as_bytes());
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn reconnect(&mut self, ctrl: &mut Control) -> Result<Option<Ending>> {
        let bootstrap = ctrl
            .call(
                "session.bootstrap",
                json!({
                    "event_scope": "all",
                    "preferred_session_id": self.session_id,
                }),
            )
            .await?;
        let Some(view) = bootstrap
            .get("selected_session")
            .and_then(|selected| selected.get("view"))
        else {
            return Ok(Some(Ending::Session));
        };
        if let Some(client_id) = bootstrap.get("client_id").and_then(Value::as_str) {
            self.client_id = client_id.to_owned();
        }
        self.fallback_title = session::fallback_title_for(&bootstrap, view, &self.block_id);
        if let Ok(size) = crossterm::terminal::size() {
            self.size = size;
        }
        // A dropped connection gives the block back to its owner, unless
        // another client claimed it meanwhile. Claim it again only when
        // nobody else holds it.
        let owner = session::owner_of(view, &self.block_id);
        if owner.is_some_and(|owner| owner != self.client_id) {
            self.owns = false;
            self.reconnect_data(ctrl).await?;
            return Ok(None);
        }
        if let Err(error) = start_take(ctrl, self.block())?.finish().await {
            // A refusal while the block is still in the view is worth another
            // try. A missing block is not.
            if session::has_block(view, &self.block_id) {
                return Err(error);
            }
            return Ok(Some(Ending::Block));
        }
        self.owns = true;
        self.sync(ctrl, Push::Both).await?;
        self.reconnect_data(ctrl).await?;
        Ok(None)
    }

    async fn reconnect_data(&mut self, ctrl: &mut Control) -> Result<()> {
        match Data::resume(self.server, self.data.token, self.data.received).await {
            Ok(data) => {
                self.filter = Filter::new(data.nonce);
                self.data = data;
                Ok(())
            }
            Err(_) => {
                let ticket = ticket(ctrl, self.block()).await?;
                self.data = Data::open(self.server, &ticket).await?;
                self.filter = Filter::new(self.data.nonce);
                self.pending.clear();
                self.primed = false;
                Ok(())
            }
        }
    }
}

const DETACH_SEQUENCES: [&[u8]; 8] = [
    b"\x1c",
    b"\x1b[92;5u",
    b"\x1b[92;5:1u",
    b"\x1b[92;5:2u",
    b"\x1b[92:124;5u",
    b"\x1b[92:124;5:1u",
    b"\x1b[92:124;5:2u",
    b"\x1b[27;5;92~",
];

/// Splits `bytes` before the earliest detach sequence, returning
/// `(prefix_before_detach, Some(tail_after_detach))` when found or
/// `(bytes, None)` otherwise.
fn split_at_detach(bytes: &[u8]) -> (&[u8], Option<&[u8]>) {
    let earliest = DETACH_SEQUENCES
        .iter()
        .filter_map(|seq| {
            bytes
                .windows(seq.len())
                .position(|window| window == *seq)
                .map(|pos| (pos, seq.len()))
        })
        .min_by_key(|&(pos, _)| pos);
    match earliest {
        Some((pos, len)) => (&bytes[..pos], Some(&bytes[pos + len..])),
        None => (bytes, None),
    }
}

fn contains_detach(bytes: &[u8]) -> bool {
    split_at_detach(bytes).1.is_some()
}

/// Asks the host terminal for its default colors and its whole 256-color
/// palette. DA1 (`ESC [ c`) acts as a completion sentinel because terminals
/// answer queries in order and always support DA1, even if they ignore OSC 4
/// or OSC 10.
fn theme_query() -> String {
    let mut query = String::from("\x1b]10;?\x07\x1b]11;?\x07\x1b]12;?\x07");
    for index in 0..=255 {
        query.push_str(&format!("\x1b]4;{index};?\x07"));
    }
    query.push_str("\x1b[c");
    query
}

/// The Rex server's `libghostty-vt` answers terminal queries on the server
/// side, so forwarding the local terminal's duplicate replies into
/// `com.superlogical.terminal.write` would inject unconsumed escape sequences
/// into the remote PTY. The replies still carry the host's colors, which is why
/// they are kept rather than dropped.
fn split_replies(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut replies = Vec::new();
    let mut typed = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 1 < bytes.len() {
            let end = match bytes[i + 1] {
                b']' => osc_reply_end(&bytes[i..]),
                b'[' => csi_reply_end(&bytes[i..]),
                _ => None,
            };
            if let Some(end) = end {
                replies.extend_from_slice(&bytes[i..i + end]);
                i += end;
                continue;
            }
        }
        typed.push(bytes[i]);
        i += 1;
    }
    (replies, typed)
}

/// Holds a reply that arrived only partly: one `theme_query` answer is larger
/// than the 4096-byte reads the input thread hands out, so replies regularly
/// straddle two of them. Half a reply looks like typed input on its own and
/// would be forwarded into the block's PTY, whose program echoes the bytes.
#[derive(Default)]
struct Replies {
    held: Vec<u8>,
    /// True when `held` came from a startup probe tail or an active reply burst
    /// rather than standalone typing, so detaching drops it instead of writing
    /// a truncated host reply into the remote PTY.
    held_from_reply: bool,
    /// When the host has been silent long enough for `held` to be typing.
    until: Option<Instant>,
    /// When the last read carried (or a query just solicited) a reply, so the
    /// host may still be sending one.
    answered: Option<Instant>,
}

impl Replies {
    fn push(&mut self, bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let now = Instant::now();
        let resumed = !self.held.is_empty();
        let was_from_reply = self.held_from_reply;
        let answering = self.answered.is_some_and(|at| now < at + REPLY_HOLD);
        let mut pending = std::mem::take(&mut self.held);
        pending.extend_from_slice(bytes);
        let cut = reply_tail(&pending).unwrap_or(pending.len());
        let (replies, mut typed) = split_replies(&pending[..cut]);
        let mut fragment = pending.split_off(cut);
        // Nothing here answered a query, so an opener at the end is a keypress:
        // holding it would merge it with the next key into an Alt combination.
        // A reply burst never arrives as one or two bytes.
        if !resumed && !answering && replies.is_empty() && bare_opener(&fragment) {
            typed.extend_from_slice(&fragment);
            fragment.clear();
        }
        let from_reply = !replies.is_empty() || answering || (resumed && was_from_reply);
        self.hold_at(fragment, from_reply, now);
        self.answered = (!replies.is_empty()).then_some(now);
        (replies, typed)
    }

    /// Keeps a probe-tail fragment back for the read that finishes it, and
    /// starts the clock that gives up on it.
    fn hold(&mut self, fragment: Vec<u8>) {
        self.hold_at(fragment, true, Instant::now());
    }

    /// Marks that a host query was just sent so a split first chunk is treated
    /// as a reply fragment rather than typed input.
    fn expect_reply(&mut self) {
        self.answered = Some(Instant::now());
    }

    fn hold_at(&mut self, fragment: Vec<u8>, from_reply: bool, now: Instant) {
        self.until = (!fragment.is_empty()).then(|| now + REPLY_HOLD);
        self.held_from_reply = !fragment.is_empty() && from_reply;
        self.held = fragment;
    }

    /// When the host has been silent long enough for `held` to be typing.
    fn due(&self) -> Option<Instant> {
        self.until
    }

    /// Postpones the clock while queued input can still finish the fragment.
    fn defer(&mut self) {
        if !self.held.is_empty() {
            self.until = Some(Instant::now() + REPLY_HOLD);
        }
    }

    /// Hands back a fragment the host stopped sending, which was typing.
    fn give_up(&mut self) -> Vec<u8> {
        self.until = None;
        self.answered = None;
        self.held_from_reply = false;
        std::mem::take(&mut self.held)
    }

    /// Like `give_up`, but drops fragments that originated from a host reply
    /// stream so detaching mid-reply does not inject escape garbage into the PTY.
    fn give_up_typed(&mut self) -> Vec<u8> {
        let from_reply = self.held_from_reply;
        let held = self.give_up();
        if from_reply { Vec::new() } else { held }
    }
}

/// True for the fragments that are ambiguous on their own: the Escape key, Alt+[
/// and Alt+].
fn bare_opener(fragment: &[u8]) -> bool {
    matches!(fragment, [0x1b] | [0x1b, b'['] | [0x1b, b']'])
}

const REPLY_CODES: [&[u8]; 4] = [b"4", b"10", b"11", b"12"];

/// Where a reply that is still arriving starts, if the buffer ends inside one.
/// An unfinished reply runs to the end of the buffer, so its start is the first
/// ESC that opens a sequence which never closes: the terminator a reply waits
/// for can itself arrive split, as ESC then backslash.
fn reply_tail(bytes: &[u8]) -> Option<usize> {
    bytes
        .iter()
        .enumerate()
        .filter(|&(_, &b)| b == 0x1b)
        .map(|(start, _)| start)
        .find(|&start| tail_unfinished(&bytes[start..]))
}

/// True while the reply starting at tail has not finished arriving. Whether a
/// lone ESC or a bare opener really is one is up to `Replies`, which knows what
/// the rest of the read held.
fn tail_unfinished(tail: &[u8]) -> bool {
    if tail.len() > MAX_HELD_REPLY {
        return false;
    }
    match tail {
        [0x1b] => true,
        [0x1b, b']', rest @ ..] => osc_open(rest),
        [0x1b, b'[', rest @ ..] => csi_open(rest),
        _ => false,
    }
}

/// True while `rest` is the unfinished body of an `OSC 4` or `OSC 10`/`11`/`12`
/// reply.
fn osc_open(rest: &[u8]) -> bool {
    if rest.contains(&0x07) || rest.windows(2).any(|pair| pair == b"\x1b\\") {
        return false;
    }
    let end = rest
        .iter()
        .position(|&b| !b.is_ascii_digit())
        .unwrap_or(rest.len());
    let code = &rest[..end];
    if end < rest.len() {
        // The code is complete, so both `;` and a reply code are required.
        return rest[end] == b';' && REPLY_CODES.contains(&code);
    }
    if code.is_empty() {
        // `ESC ]` alone is either Alt+] or an OSC reply starting up.
        return true;
    }
    REPLY_CODES.iter().any(|want| want.starts_with(code))
}

/// True while `rest` is the unfinished parameter bytes of a CSI reply. A
/// complete control sequence, and anything without the `?`/`>` that only
/// replies carry, is typing that has to reach the block untouched.
fn csi_open(rest: &[u8]) -> bool {
    if rest.iter().any(|&b| (0x40..=0x7e).contains(&b)) {
        return false;
    }
    match rest {
        [] => true,
        [b'?' | b'>', params @ ..] => params
            .iter()
            .all(|&b| b.is_ascii_digit() || b == b';' || b == b':'),
        _ => false,
    }
}

/// DECSET 2031's report: `ESC [ ? 997 ; Ps n`, where Ps is 1 for dark and 2
/// for light.
fn reports_scheme(replies: &[u8]) -> bool {
    replies.windows(7).any(|window| window == b"\x1b[?997;")
}

fn osc_reply_end(slice: &[u8]) -> Option<usize> {
    let rest = slice.strip_prefix(b"\x1b]")?;
    let semi = rest.iter().position(|&b| b == b';')?;
    let code = std::str::from_utf8(&rest[..semi]).ok()?;
    if !matches!(code, "4" | "10" | "11" | "12") {
        return None;
    }
    let body = &rest[semi + 1..];
    for (idx, &b) in body.iter().enumerate() {
        if b == 0x07 {
            return Some(2 + semi + 1 + idx + 1);
        }
        if b == 0x1b && body.get(idx + 1) == Some(&b'\\') {
            return Some(2 + semi + 1 + idx + 2);
        }
    }
    None
}

fn csi_reply_end(slice: &[u8]) -> Option<usize> {
    let rest = slice.strip_prefix(b"\x1b[")?;
    let (&prefix, params) = rest.split_first()?;
    if prefix != b'?' && prefix != b'>' {
        return None;
    }
    let end = params
        .iter()
        .position(|&b| !b.is_ascii_digit() && b != b';' && b != b':')?;
    let final_byte = params[end];
    if final_byte == b'c' || (prefix == b'?' && final_byte == b'n' && params.starts_with(b"997;")) {
        return Some(2 + 1 + end + 1);
    }
    None
}

fn parse_theme_reply(bytes: &[u8]) -> Theme {
    let mut theme = Theme::default();
    let text = String::from_utf8_lossy(bytes);
    for part in text.split("\x1b]") {
        let Some(end) = part.find('\x07').or_else(|| part.find("\x1b\\")) else {
            continue;
        };
        let body = &part[..end];
        let Some((code, rest)) = body.split_once(';') else {
            continue;
        };
        match code {
            "10" => theme.foreground = parse_osc_rgb(rest).map(|(hex, _)| hex),
            "11" => {
                if let Some((hex, (r, g, b))) = parse_osc_rgb(rest) {
                    let luma =
                        (299 * u32::from(r) + 587 * u32::from(g) + 114 * u32::from(b)) / 1000;
                    theme.scheme = Some(if luma >= 128 { "light" } else { "dark" }.to_owned());
                    theme.background = Some(hex);
                }
            }
            "12" => theme.cursor = parse_osc_rgb(rest).map(|(hex, _)| hex),
            "4" => {
                if let Some((idx_str, color_str)) = rest.split_once(';')
                    && let Ok(idx) = idx_str.parse::<u8>()
                    && let Some((hex, _)) = parse_osc_rgb(color_str)
                {
                    theme.palette.push(format!("{idx}={hex}"));
                }
            }
            _ => {}
        }
    }
    theme
}

fn parse_osc_rgb(s: &str) -> Option<(String, (u8, u8, u8))> {
    let rgb = s.strip_prefix("rgb:")?;
    let mut parts = rgb.split('/');
    let r = parse_color_channel(parts.next()?)?;
    let g = parse_color_channel(parts.next()?)?;
    let b = parse_color_channel(parts.next()?)?;
    Some((format!("#{r:02x}{g:02x}{b:02x}"), (r, g, b)))
}

fn parse_color_channel(hex: &str) -> Option<u8> {
    if hex.len() >= 2 {
        u8::from_str_radix(&hex[..2], 16).ok()
    } else if hex.len() == 1 {
        let v = u8::from_str_radix(hex, 16).ok()?;
        Some((v << 4) | v)
    } else {
        None
    }
}

fn take_utf8(buf: &mut Vec<u8>) -> String {
    let mut out = String::new();
    loop {
        match std::str::from_utf8(buf) {
            Ok(valid) => {
                out.push_str(valid);
                buf.clear();
                return out;
            }
            Err(error) => {
                let valid_len = error.valid_up_to();
                if valid_len > 0 {
                    out.push_str(std::str::from_utf8(&buf[..valid_len]).unwrap());
                    buf.drain(..valid_len);
                }
                match error.error_len() {
                    None => return out,
                    Some(invalid_len) => {
                        out.push(char::REPLACEMENT_CHARACTER);
                        buf.drain(..invalid_len);
                    }
                }
            }
        }
    }
}

fn take_write_chunk(queue: &mut String, max_bytes: usize) -> String {
    if queue.len() <= max_bytes {
        return std::mem::take(queue);
    }
    let mut split = max_bytes;
    while split > 0 && !queue.is_char_boundary(split) {
        split -= 1;
    }
    if split == 0 {
        // Never stall if max_bytes is smaller than the leading UTF-8 char.
        split = queue.chars().next().map_or(0, char::len_utf8);
    }
    let rest = queue.split_off(split);
    std::mem::replace(queue, rest)
}

async fn finish_write(inflight: &mut Option<InflightWrite>) -> Result<Value> {
    let Some(write) = inflight.as_mut() else {
        return std::future::pending().await;
    };
    let outcome = tokio::time::timeout_at(write.deadline, &mut write.rx).await;
    *inflight = None;
    match outcome {
        Ok(received) => received.map_err(|_| anyhow!("the control connection ended"))?,
        Err(_) => Err(anyhow::Error::new(CallTimeout(format!(
            "the server did not answer com.superlogical.terminal.write within {}",
            format_timeout(CALL_TIME)
        )))),
    }
}

struct PendingRpc {
    method: &'static str,
    rx: tokio::sync::oneshot::Receiver<Result<Value>>,
}

impl PendingRpc {
    fn start(ctrl: &mut Control, method: &'static str, payload: Value) -> Result<Self> {
        Ok(Self {
            method,
            rx: ctrl.start_call(method, payload)?,
        })
    }

    async fn finish(self) -> Result<Value> {
        match tokio::time::timeout(CALL_TIME, self.rx).await {
            Ok(received) => received.map_err(|_| anyhow!("the control connection ended"))?,
            Err(_) => Err(anyhow::Error::new(CallTimeout(format!(
                "the server did not answer {} within {}",
                self.method,
                format_timeout(CALL_TIME)
            )))),
        }
    }
}

fn start_take(ctrl: &mut Control, block: BlockRef<'_>) -> Result<PendingRpc> {
    PendingRpc::start(
        ctrl,
        "session.own_block",
        json!({
            "session_id": block.session_id,
            "block_ids": [block.block_id],
            "mode": "take",
        }),
    )
}

fn start_set_theme(ctrl: &mut Control, block: BlockRef<'_>, theme: &Theme) -> Result<PendingRpc> {
    PendingRpc::start(
        ctrl,
        "com.superlogical.terminal.set_theme",
        json!({
            "session_id": block.session_id,
            "block_id": block.block_id,
            "args": theme.to_json(),
        }),
    )
}

fn start_resize(
    ctrl: &mut Control,
    block: BlockRef<'_>,
    cols: u16,
    rows: u16,
) -> Result<PendingRpc> {
    PendingRpc::start(
        ctrl,
        "com.superlogical.terminal.resize",
        json!({
            "session_id": block.session_id,
            "block_id": block.block_id,
            "args": {"columns": cols, "rows": rows},
        }),
    )
}

/// Which part of the block's state to publish. A client publishes what it
/// changed while it holds the block, or both when it takes it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Push {
    Size,
    Theme,
    Both,
}

impl Push {
    fn size(self) -> bool {
        matches!(self, Self::Size | Self::Both)
    }

    fn theme(self) -> bool {
        matches!(self, Self::Theme | Self::Both)
    }
}

async fn publish(
    ctrl: &mut Control,
    block: BlockRef<'_>,
    size: (u16, u16),
    theme: &Theme,
    push: Push,
) -> Result<()> {
    let theme_call = (push.theme() && !theme.is_empty())
        .then(|| start_set_theme(ctrl, block, theme))
        .transpose()?;
    let size_call = push
        .size()
        .then(|| start_resize(ctrl, block, size.0, size.1))
        .transpose()?;
    if let Some(call) = theme_call {
        call.finish().await?;
    }
    if let Some(call) = size_call {
        call.finish().await?;
    }
    Ok(())
}

/// `extra_palette` is omitted so the server's 256-color table does not
/// overwrite the host terminal's color theme via OSC 4.
async fn format_vt(ctrl: &mut Control, block: BlockRef<'_>) -> Result<Vec<u8>> {
    let reply = ctrl
        .call(
            "com.superlogical.terminal.format",
            json!({
                "session_id": block.session_id,
                "block_id": block.block_id,
                "args": {
                    "format": "vt",
                    "trim": false,
                    "extra_cursor": true,
                    "extra_style": true,
                    "extra_modes": true,
                    "extra_scrolling_region": true,
                    "extra_tabstops": true,
                    "extra_keyboard": true,
                    "extra_kitty_keyboard": true,
                    "extra_charsets": true,
                    "extra_hyperlink": true,
                    "extra_protection": true,
                    "extra_pwd": true,
                    "max_bytes": MAX_BLOB_BYTES,
                },
            }),
        )
        .await?;
    let content = reply
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let Some(id) = reply.get("id").and_then(Value::as_i64) else {
        return Ok(content.into_bytes());
    };
    let full = read_chunks(
        ctrl,
        block,
        "com.superlogical.terminal.blob_read",
        id,
        content,
    )
    .await?;
    Ok(full.into_bytes())
}

async fn clipboard(ctrl: &mut Control, block: BlockRef<'_>, id: i64) -> Result<String> {
    read_chunks(
        ctrl,
        block,
        "com.superlogical.terminal.clipboard_read",
        id,
        String::new(),
    )
    .await
}

async fn read_chunks(
    ctrl: &mut Control,
    block: BlockRef<'_>,
    method: &str,
    id: i64,
    out: String,
) -> Result<String> {
    read_chunks_with_limits(
        ctrl,
        block,
        method,
        id,
        out,
        tokio::time::Instant::now() + BLOB_READ_TIME,
        MAX_TOTAL_BLOB_BYTES,
    )
    .await
}

async fn read_chunks_with_limits(
    ctrl: &mut Control,
    block: BlockRef<'_>,
    method: &str,
    id: i64,
    mut out: String,
    deadline: tokio::time::Instant,
    max_total_bytes: usize,
) -> Result<String> {
    if out.len() > max_total_bytes {
        bail!("{method} exceeded maximum size of {max_total_bytes} bytes");
    }
    loop {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .ok_or_else(|| {
                anyhow::Error::new(CallTimeout(format!(
                    "the server did not finish {method} within {}",
                    format_timeout(BLOB_READ_TIME)
                )))
            })?;
        let part = ctrl
            .call_with_timeout(
                method,
                json!({
                    "session_id": block.session_id,
                    "block_id": block.block_id,
                    "args": {"id": id, "offset": out.len(), "max_bytes": MAX_BLOB_BYTES},
                }),
                remaining,
            )
            .await?;
        let data = part.get("data").and_then(Value::as_str).unwrap_or_default();
        let eof = part.get("eof").and_then(Value::as_bool).unwrap_or(true);
        if out.len().saturating_add(data.len()) > max_total_bytes {
            bail!("{method} exceeded maximum size of {max_total_bytes} bytes");
        }
        out.push_str(data);
        if eof {
            break;
        }
        if data.is_empty() {
            bail!("{method} returned empty chunk before eof");
        }
    }
    Ok(out)
}

/// Resolves when a held fragment has waited long enough to count as typing, and
/// never while nothing is held.
async fn stalled(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at.into()).await,
        None => std::future::pending::<()>().await,
    }
}

struct InputReader {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    wake: Option<std::io::PipeWriter>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl InputReader {
    fn spawn() -> Result<Self> {
        Self::spawn_reader(std::io::stdin())
    }

    fn spawn_reader(input: impl Read + AsRawFd + Send + 'static) -> Result<Self> {
        let (wake_rd, wake_wr) = std::io::pipe()?;
        let (tx, rx) = mpsc::unbounded_channel();
        let thread = std::thread::spawn(move || {
            read_until_wake(input, wake_rd, tx);
        });
        Ok(Self {
            rx,
            wake: Some(wake_wr),
            thread: Some(thread),
        })
    }

    #[cfg(test)]
    fn from_channel(rx: mpsc::UnboundedReceiver<Vec<u8>>) -> Self {
        Self {
            rx,
            wake: None,
            thread: None,
        }
    }

    async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }

    fn try_recv(&mut self) -> Option<Vec<u8>> {
        self.rx.try_recv().ok()
    }

    fn is_empty(&self) -> bool {
        self.rx.is_empty()
    }

    fn drain_detach(&mut self) -> bool {
        let mut saw_detach = false;
        while let Some(bytes) = self.try_recv() {
            if contains_detach(&bytes) {
                saw_detach = true;
            }
        }
        saw_detach
    }

    fn stop(&mut self) {
        if let Some(mut wake) = self.wake.take() {
            let _ = wake.write_all(&[1]);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    /// Stops the background reader thread so it cannot steal subsequent keys
    /// from the picker, and reports whether any already-queued chunks carried a
    /// second detach key.
    fn stop_and_drain_detach(&mut self) -> bool {
        self.stop();
        self.drain_detach()
    }
}

impl Drop for InputReader {
    fn drop(&mut self) {
        self.stop();
    }
}

fn read_until_wake(
    mut input: impl Read + AsRawFd,
    wake_rd: std::io::PipeReader,
    tx: mpsc::UnboundedSender<Vec<u8>>,
) {
    let input_fd = input.as_raw_fd();
    let wake_fd = wake_rd.as_raw_fd();
    let mut buf = [0u8; 4096];
    loop {
        let mut fds = [
            libc_pollfd {
                fd: input_fd,
                events: POLLIN,
                revents: 0,
            },
            libc_pollfd {
                fd: wake_fd,
                events: POLLIN,
                revents: 0,
            },
        ];
        let ready = unsafe { poll(fds.as_mut_ptr(), 2, -1) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if fds[1].revents != 0 {
            return;
        }
        if fds[0].revents != 0 {
            match input.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        return;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return,
            }
        }
    }
}

enum Recovered {
    Live,
    Detach { double: bool },
    Ended(Ending),
}

async fn recover(
    token: &mut Option<String>,
    ctrl: &mut Control,
    events: &mut Events,
    attached: &mut Attached<'_>,
    input: &mut InputReader,
) -> Result<Recovered> {
    let mut delay = RETRY_FIRST;
    loop {
        match attempt(token, ctrl, events, attached).await {
            Ok(None) => {
                // Keys pressed while the link was down have nowhere to go,
                // and the reply a held fragment belonged to is gone with them.
                while input.try_recv().is_some() {}
                attached.replies = Replies::default();
                attached.input_buf.clear();
                attached.write_queue.clear();
                attached.write_inflight = None;
                return Ok(Recovered::Live);
            }
            Ok(Some(ending)) => return Ok(Recovered::Ended(ending)),
            Err(_) => {
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    Some(bytes) = input.recv() => {
                        if let Some(tail) = split_at_detach(&bytes).1 {
                            return Ok(Recovered::Detach {
                                double: contains_detach(tail),
                            });
                        }
                    }
                }
                delay = backoff(delay);
            }
        }
    }
}

async fn attempt(
    token: &mut Option<String>,
    ctrl: &mut Control,
    events: &mut Events,
    attached: &mut Attached<'_>,
) -> Result<Option<Ending>> {
    if ctrl
        .call_with_timeout("server.version", Value::Null, PROBE_TIME)
        .await
        .is_err()
    {
        let (new_ctrl, new_events) = Control::connect(attached.server, token.as_deref()).await?;
        *token = new_ctrl.reconnect_token.clone();
        *ctrl = new_ctrl;
        *events = new_events;
    }
    attached.reconnect(ctrl).await
}

fn backoff(delay: Duration) -> Duration {
    (delay * 2).min(RETRY_MAX)
}

fn transient(ctrl: &Control, error: &anyhow::Error) -> bool {
    if ctrl.is_lost()
        || error.downcast_ref::<StreamClosed>().is_some()
        || error.downcast_ref::<CallTimeout>().is_some()
    {
        return true;
    }
    match error.downcast_ref::<proto::ApiError>() {
        Some(error) => error.status == 409,
        None => false,
    }
}

fn write_target_gone(error: &anyhow::Error) -> bool {
    error.downcast_ref::<proto::ApiError>().is_some_and(|api| {
        api.status == 404
            || matches!(
                api.code.as_str(),
                "not_found" | "block_not_found" | "session_not_found" | "block_closed"
            )
    })
}

fn data_ended() -> anyhow::Error {
    anyhow::Error::new(StreamClosed {
        code: None,
        reason: String::new(),
    })
}

fn stream_lost(error: anyhow::Error) -> anyhow::Error {
    match error.downcast::<StreamClosed>() {
        Ok(closed) => anyhow::Error::new(closed),
        Err(error) => anyhow::Error::new(StreamClosed {
            code: None,
            reason: error.to_string(),
        }),
    }
}

async fn detach(ctrl: &mut Control, attached: &mut Attached<'_>) {
    let deadline = tokio::time::Instant::now() + DETACH_TIME;
    if !ctrl.is_lost() {
        let _ = attached.drain_writes(ctrl, deadline).await;
    }
    detach_session(ctrl, &attached.session_id, deadline).await;
}

async fn detach_session(ctrl: &mut Control, session_id: &str, deadline: tokio::time::Instant) {
    if ctrl.is_lost() {
        return;
    }
    let timeout = deadline
        .checked_duration_since(tokio::time::Instant::now())
        .unwrap_or(Duration::from_millis(200));
    let _ = ctrl
        .call_with_timeout("session.detach", json!({"session_id": session_id}), timeout)
        .await;
}

fn start_ticket(ctrl: &mut Control, block: BlockRef<'_>) -> Result<PendingRpc> {
    PendingRpc::start(
        ctrl,
        "data.connect",
        json!({
            "session_id": block.session_id,
            "block_id": block.block_id,
            "data_ref_id": DATA_REF,
            "subprotocol": data::SUBPROTOCOL,
        }),
    )
}

fn parse_ticket(reply: &Value) -> Result<String> {
    reply
        .get("ticket")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("data.connect returned no ticket"))
}

async fn ticket(ctrl: &mut Control, block: BlockRef<'_>) -> Result<String> {
    parse_ticket(&start_ticket(ctrl, block)?.finish().await?)
}

fn closed_block(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<StreamClosed>()
        .is_some_and(StreamClosed::is_block_closed)
}

struct Screen {
    stdout: std::io::Stdout,
    entered: bool,
    terminal_mode: TerminalMode,
}

impl Screen {
    fn enter(terminal_mode: TerminalMode) -> Result<Self> {
        enable_raw_mode()?;
        let mut stdout = std::io::stdout();
        // Clear any leftover OSC 4/10/11/12 overrides before probing the host
        // terminal's theme, and save the host title so RESET_MODES can restore it.
        stdout.write_all(RESET_COLORS)?;
        stdout.write_all(b"\x1b[22;0t")?;
        stdout.flush()?;
        Ok(Self {
            stdout,
            entered: true,
            terminal_mode,
        })
    }

    /// Returns the theme and the tail of a reply the deadline cut off.
    fn probe_theme(&mut self) -> (Theme, Vec<u8>) {
        if self.stdout.write_all(theme_query().as_bytes()).is_err() || self.stdout.flush().is_err()
        {
            return (Theme::default(), Vec::new());
        }

        let stdin = std::io::stdin();
        let fd = stdin.as_raw_fd();
        let deadline = Instant::now() + THEME_PROBE_TIMEOUT;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];

        while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            let timeout_ms = (remaining.as_millis() as i32).max(1);
            let mut pfd = libc_pollfd {
                fd,
                events: POLLIN,
                revents: 0,
            };
            let ready = unsafe { poll(&mut pfd, 1, timeout_ms) };
            if ready <= 0 {
                break;
            }
            let Ok(n) = (&stdin).read(&mut chunk) else {
                break;
            };
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if has_da1_reply(&buf) {
                break;
            }
        }
        let _ = self
            .stdout
            .write_all(WATCH_SCHEME)
            .and_then(|()| self.stdout.flush());
        let tail = reply_tail(&buf).map_or_else(Vec::new, |start| buf[start..].to_vec());
        (parse_theme_reply(&buf), tail)
    }

    fn out(&mut self) -> &mut std::io::Stdout {
        &mut self.stdout
    }

    fn leave(&mut self) -> Result<()> {
        if !self.entered {
            return Ok(());
        }
        self.entered = false;
        self.stdout.write_all(RESET_MODES)?;
        self.stdout.flush()?;
        if self.terminal_mode == TerminalMode::RestoreOnLeave {
            disable_raw_mode()?;
        }
        Ok(())
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        let _ = self.leave();
    }
}

const POLLIN: i16 = 0x0001;

#[repr(C)]
struct libc_pollfd {
    fd: i32,
    events: i16,
    revents: i16,
}

unsafe extern "C" {
    fn poll(fds: *mut libc_pollfd, nfds: usize, timeout: i32) -> i32;
}

fn has_da1_reply(bytes: &[u8]) -> bool {
    for (i, &b) in bytes.iter().enumerate() {
        if b == 0x1b
            && bytes.get(i + 1) == Some(&b'[')
            && bytes.get(i + 2) == Some(&b'?')
            && let Some(end) = bytes[i + 3..]
                .iter()
                .position(|&c| !c.is_ascii_digit() && c != b';')
            && bytes[i + 3 + end] == b'c'
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{
        Attached, BlockSelection, Ending, Flow, InflightWrite, InputReader, RETRY_FIRST, RETRY_MAX,
        Replies, Theme, backoff, closed_block, contains_detach, detach, finish_write,
        has_da1_reply, parse_theme_reply, read_chunks_with_limits, reports_scheme, split_at_detach,
        split_replies, take_utf8, take_write_chunk, theme_query, transient, write_target_gone,
    };
    use crate::rex::BlockRef;
    use crate::rex::control::{CallTimeout, Control};
    use crate::rex::data::StreamClosed;
    use crate::rex::proto::ApiError;
    use base64::Engine as _;
    use futures_util::{SinkExt, StreamExt};
    use serde_json::{Value, json};
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

    fn snapshot_header() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"GHOSTSNP\x01\x00");
        buf.extend_from_slice(&6u16.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf
    }

    #[test]
    fn recognizes_detach_key_in_legacy_kitty_and_xterm_modes_including_batched_reads() {
        for seq in [
            b"\x1c".as_slice(),
            b"\x1b[92;5u".as_slice(),
            b"\x1b[92;5:1u".as_slice(),
            b"\x1b[92;5:2u".as_slice(),
            b"\x1b[92:124;5u".as_slice(),
            b"\x1b[92:124;5:1u".as_slice(),
            b"\x1b[27;5;92~".as_slice(),
        ] {
            assert_eq!(split_at_detach(seq), (b"".as_slice(), Some(b"".as_slice())));
            assert!(contains_detach(seq));
        }

        assert_eq!(
            split_at_detach(b"abc\x1c"),
            (b"abc".as_slice(), Some(b"".as_slice()))
        );
        assert_eq!(
            split_at_detach(b"abc\x1b[92;5u"),
            (b"abc".as_slice(), Some(b"".as_slice()))
        );
        assert_eq!(
            split_at_detach(b"a\x1b[27;5;92~tail"),
            (b"a".as_slice(), Some(b"tail".as_slice()))
        );
        assert_eq!(
            split_at_detach(b"\x1ctail"),
            (b"".as_slice(), Some(b"tail".as_slice()))
        );

        // Double detach in a single read exposes the second sequence in the tail.
        for pair in [
            b"\x1c\x1c".as_slice(),
            b"abc\x1c\x1c".as_slice(),
            b"\x1b[92;5u\x1b[92;5u".as_slice(),
            b"\x1c\x1b[92;5u".as_slice(),
            b"\x1b[27;5;92~\x1c".as_slice(),
        ] {
            let (_, tail) = split_at_detach(pair);
            assert!(
                tail.is_some_and(contains_detach),
                "expected second detach in tail of {pair:?}"
            );
        }

        assert_eq!(split_at_detach(b"\\"), (b"\\".as_slice(), None));
        assert_eq!(
            split_at_detach(b"\x1b[92;1u"),
            (b"\x1b[92;1u".as_slice(), None)
        );
        assert_eq!(split_at_detach(b"hello"), (b"hello".as_slice(), None));
    }

    #[tokio::test]
    async fn input_reader_stops_without_consuming_subsequent_bytes_and_drains_queued_detach() {
        use std::io::{Read, Write};

        let (input_rd, mut input_wr) = std::io::pipe().unwrap();
        // Keep a duplicate read handle on the same pipe so we can verify bytes
        // written after stop() are not stolen by the background thread.
        let mut reader_after = input_rd.try_clone().unwrap();
        let mut reader = InputReader::spawn_reader(input_rd).unwrap();

        input_wr.write_all(b"hello").unwrap();
        let first = tokio::time::timeout(Duration::from_secs(1), reader.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first, b"hello");

        // Queue a detach byte and wait until the reader thread has placed it in the channel.
        input_wr.write_all(b"\x1c").unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while reader.is_empty() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(reader.stop_and_drain_detach());

        // Bytes written after stop() stay in the pipe for the next reader (e.g. picker).
        input_wr.write_all(b"\x1cnext").unwrap();
        let mut remaining = [0u8; 16];
        let n = reader_after.read(&mut remaining).unwrap();
        assert_eq!(&remaining[..n], b"\x1cnext");
    }

    #[test]
    fn parses_osc_theme_replies_and_detects_light_or_dark_scheme() {
        let reply = concat!(
            "\x1b]10;rgb:1111/2222/3333\x1b\\",
            "\x1b]11;rgb:f8f8/f9f9/fafa\x07",
            "\x1b]12;rgb:00/55/ff\x07",
            "\x1b]4;0;rgb:0000/0000/0000\x1b\\",
            "\x1b]4;1;rgb:a6a6/0000/0000\x07",
            "\x1b[?62;22c",
        )
        .as_bytes();
        assert!(has_da1_reply(reply));
        let theme = parse_theme_reply(reply);
        assert_eq!(theme.foreground.as_deref(), Some("#112233"));
        assert_eq!(theme.background.as_deref(), Some("#f8f9fa"));
        assert_eq!(theme.cursor.as_deref(), Some("#0055ff"));
        assert_eq!(theme.scheme.as_deref(), Some("light"));
        assert_eq!(theme.palette, vec!["0=#000000", "1=#a60000"]);
    }

    #[test]
    fn separates_host_query_replies_from_typed_input() {
        let mixed = concat!(
            "abc",
            "\x1b]4;232;rgb:0808/0808/0808\x07",
            "\x1b]11;rgb:ffff/ffff/ffff\x1b\\",
            "\x1b[?997;2n",
            "\x1b[?62;22c",
            "\x1b[>1;10;0c",
            "def\x1b[A",
        )
        .as_bytes();
        let (replies, typed) = split_replies(mixed);
        assert_eq!(typed, b"abcdef\x1b[A");
        assert_eq!(
            replies,
            concat!(
                "\x1b]4;232;rgb:0808/0808/0808\x07",
                "\x1b]11;rgb:ffff/ffff/ffff\x1b\\",
                "\x1b[?997;2n",
                "\x1b[?62;22c",
                "\x1b[>1;10;0c",
            )
            .as_bytes()
        );
    }

    fn palette_reply(terminator: &[u8], entries: usize) -> Vec<u8> {
        let mut stream = Vec::new();
        for code in ["10", "11", "12"] {
            stream.extend_from_slice(format!("\x1b]{code};rgb:cdcd/d6d6/f4f4").as_bytes());
            stream.extend_from_slice(terminator);
        }
        for index in 0..entries {
            stream.extend_from_slice(format!("\x1b]4;{index};rgb:0000/0000/0000").as_bytes());
            stream.extend_from_slice(terminator);
        }
        stream.extend_from_slice(b"\x1b[?62;22c");
        stream
    }

    #[test]
    fn holds_replies_split_across_reads_until_the_rest_arrives() {
        let mut replies = Replies::default();
        let (found, typed) = replies.push(b"ab\x1b]4;147;rgb:000");
        assert!(found.is_empty());
        assert_eq!(typed, b"ab");

        let (found, typed) = replies.push(b"0/0000/0000\x1b\\\x1b");
        assert!(typed.is_empty());
        assert_eq!(found, b"\x1b]4;147;rgb:0000/0000/0000\x1b\\");

        let (found, typed) = replies.push(b"[");
        assert!(found.is_empty());
        assert!(typed.is_empty());

        let (found, typed) = replies.push(b"?62;22c");
        assert!(typed.is_empty());
        assert_eq!(found, b"\x1b[?62;22c");
        assert!(replies.due().is_none());
    }

    #[test]
    fn forwards_nothing_when_a_read_splits_a_palette_reply() {
        for terminator in [b"\x07".as_slice(), b"\x1b\\".as_slice()] {
            let stream = palette_reply(terminator, 256);
            // A cut of one or two bytes is the Escape key or Alt+[ rather than
            // the start of a reply, so the burst starts at three.
            for cut in 3..stream.len() {
                let mut replies = Replies::default();
                let (mut found, typed) = replies.push(&stream[..cut]);
                assert_eq!(typed, b"", "typed before the split at {cut}");
                let (kept, typed) = replies.push(&stream[cut..]);
                assert_eq!(typed, b"", "typed after the split at {cut}");
                found.extend_from_slice(&kept);
                assert_eq!(found, stream, "replies around the split at {cut}");
                assert!(replies.due().is_none(), "held after the split at {cut}");
            }
        }
    }

    #[test]
    fn holds_a_lone_escape_that_arrives_right_after_a_reply() {
        let mut replies = Replies::default();
        let (found, typed) = replies.push(b"\x1b]11;rgb:ffff/ffff/ffff\x07\x1b");
        assert_eq!(found, b"\x1b]11;rgb:ffff/ffff/ffff\x07");
        assert!(typed.is_empty());
        assert!(replies.due().is_some());

        let (found, typed) = replies.push(b"]4;147;rgb:0000/0000/0000\x07");
        assert!(typed.is_empty());
        assert_eq!(found, b"\x1b]4;147;rgb:0000/0000/0000\x07");
        assert!(replies.due().is_none());
    }

    #[test]
    fn hands_a_lone_escape_back_when_the_host_stays_silent() {
        let mut replies = Replies::default();
        assert!(replies.push(b"\x1b]11;rgb:ffff/ffff/ffff\x07").1.is_empty());
        assert!(replies.push(b"\x1b").1.is_empty());
        assert!(replies.due().is_some());
        assert_eq!(replies.give_up(), b"\x1b");
        assert!(replies.due().is_none());
    }

    #[test]
    fn hands_a_half_reply_back_only_after_the_host_stops_sending() {
        let mut replies = Replies::default();
        let (found, typed) = replies.push(b"\x1b]4;147;rgb:000");
        assert!(found.is_empty());
        assert!(typed.is_empty());

        let (found, typed) = replies.push(b"0/0000/0000\x07");
        assert!(typed.is_empty());
        assert_eq!(found, b"\x1b]4;147;rgb:0000/0000/0000\x07");

        let (found, typed) = replies.push(b"\x1b]4;147;rgb:000");
        assert!(found.is_empty() && typed.is_empty());
        assert_eq!(replies.give_up(), b"\x1b]4;147;rgb:000");
    }

    #[test]
    fn finishes_a_reply_the_startup_probe_read_only_the_start_of() {
        let mut replies = Replies::default();
        replies.hold(b"\x1b]11;rgb:ffff".to_vec());
        let (found, typed) = replies.push(b"/ffff/ffff\x07");
        assert!(typed.is_empty());
        assert_eq!(found, b"\x1b]11;rgb:ffff/ffff/ffff\x07");
    }

    #[test]
    fn forwards_input_that_only_looks_like_the_start_of_a_reply() {
        let mut replies = Replies::default();
        // The Escape key, Alt+[ and Alt+] on their own are keypresses, not the
        // start of a reply.
        assert_eq!(replies.push(b"\x1b").1, b"\x1b");
        assert_eq!(replies.push(b"\x1b[").1, b"\x1b[");
        assert_eq!(replies.push(b"\x1b]").1, b"\x1b]");
        assert_eq!(replies.push(b"\x1b[A").1, b"\x1b[A");
        assert_eq!(replies.push(b"\x1b[<0;3;4M").1, b"\x1b[<0;3;4M");
        assert_eq!(replies.push(b"\x1b]0;title\x07").1, b"\x1b]0;title\x07");
        assert_eq!(replies.push(b"\x1b]abc\r").1, b"\x1b]abc\r");
        assert_eq!(replies.push(b"\x1b[?x").1, b"\x1b[?x");
        // OSC 1 is a title query, not a palette reply.
        assert_eq!(replies.push(b"\x1b]1;title\x07").1, b"\x1b]1;title\x07");
    }

    #[test]
    fn give_up_typed_flushes_standalone_typing_but_drops_host_reply_fragments() {
        // Standalone ambiguous input is flushed on detach.
        let mut replies = Replies::default();
        assert_eq!(replies.push(b"abc\x1b[?").1, b"abc");
        assert_eq!(replies.give_up_typed(), b"\x1b[?");

        // A startup probe tail is dropped on detach instead of entering the PTY.
        let mut replies = Replies::default();
        replies.hold(b"\x1b]4;12;rgb:ffff/".to_vec());
        assert!(replies.give_up_typed().is_empty());

        // A partial reply trailing a host reply burst is dropped on detach.
        let mut replies = Replies::default();
        let (found, typed) = replies.push(b"\x1b]10;rgb:1111/2222/3333\x07\x1b]4;12;rgb:ffff/");
        assert_eq!(found, b"\x1b]10;rgb:1111/2222/3333\x07");
        assert!(typed.is_empty());
        assert!(replies.give_up_typed().is_empty());

        // A split first chunk after `expect_reply` (e.g. `refresh_theme`) is dropped.
        let mut replies = Replies::default();
        replies.expect_reply();
        assert!(replies.push(b"\x1b]10;rgb:ffff/").1.is_empty());
        assert!(replies.give_up_typed().is_empty());
    }

    #[test]
    fn spots_color_scheme_reports_from_the_host() {
        let (replies, typed) = split_replies(b"\x1b[?997;2n");
        assert!(reports_scheme(&replies));
        assert!(typed.is_empty());

        let (replies, _) = split_replies(b"\x1b]11;rgb:0000/0000/0000\x07");
        assert!(!reports_scheme(&replies));
    }

    #[test]
    fn asks_the_host_for_its_whole_palette_and_a_da1_sentinel() {
        let query = theme_query();
        assert!(query.starts_with("\x1b]10;?\x07\x1b]11;?\x07\x1b]12;?\x07"));
        assert!(query.contains("\x1b]4;0;?\x07"));
        assert!(query.contains("\x1b]4;255;?\x07"));
        assert!(!query.contains("\x1b]4;256;?\x07"));
        assert!(query.ends_with("\x1b[c"));
    }

    #[test]
    fn buffers_incomplete_utf8_until_remaining_bytes_arrive() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"hi \xF0\x9F");
        assert_eq!(take_utf8(&mut buf), "hi ");
        assert_eq!(buf, b"\xF0\x9F");

        buf.extend_from_slice(b"\xA6\x80!");
        assert_eq!(take_utf8(&mut buf), "🦀!");
        assert!(buf.is_empty());
    }

    #[test]
    fn waits_longer_between_reconnect_tries_but_not_forever() {
        let mut delay = RETRY_FIRST;
        let mut waits = Vec::new();
        while delay < RETRY_MAX {
            waits.push(delay.as_millis());
            delay = backoff(delay);
        }
        assert_eq!(waits, vec![250, 500, 1000, 2000, 4000]);
        assert_eq!(delay, Duration::from_secs(5));
        assert_eq!(backoff(delay), Duration::from_secs(5));
    }

    #[test]
    fn detects_closed_block_stream_error() {
        let err_4000 = anyhow::Error::new(StreamClosed {
            code: Some(4000),
            reason: String::new(),
        });
        assert!(closed_block(&err_4000));

        let err_reason = anyhow::Error::new(StreamClosed {
            code: Some(1000),
            reason: "block closed".to_owned(),
        });
        assert!(closed_block(&err_reason));

        let err_other = anyhow::Error::new(StreamClosed {
            code: Some(1001),
            reason: "keepalive timeout".to_owned(),
        });
        assert!(!closed_block(&err_other));
    }

    #[tokio::test]
    async fn attaches_primes_stream_and_passes_through_io_and_events() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (ctrl_tcp, _) = listener.accept().await.unwrap();
            #[allow(
                clippy::result_large_err,
                reason = "tungstenite fixes the callback error type"
            )]
            let mut ctrl_ws = tokio_tungstenite::accept_hdr_async(
                ctrl_tcp,
                |req: &Request, mut res: Response| {
                    if let Some(proto) = req.headers().get("Sec-WebSocket-Protocol") {
                        res.headers_mut()
                            .insert("Sec-WebSocket-Protocol", proto.clone());
                    }
                    Ok(res)
                },
            )
            .await
            .unwrap();

            let _hello = ctrl_ws.next().await.unwrap().unwrap();
            ctrl_ws
                .send(Message::Text(
                    json!({
                        "type": "welcome",
                        "api_revision": 8,
                        "client": {"reconnect_token": "tok-1"}
                    })
                    .to_string()
                    .into(),
                ))
                .await
                .unwrap();

            let data_task = tokio::spawn(async move {
                let (data_tcp, _) = listener.accept().await.unwrap();
                #[allow(
                    clippy::result_large_err,
                    reason = "tungstenite fixes the callback error type"
                )]
                let mut data_ws = tokio_tungstenite::accept_hdr_async(
                    data_tcp,
                    |req: &Request, mut res: Response| {
                        if let Some(proto) = req.headers().get("Sec-WebSocket-Protocol") {
                            res.headers_mut()
                                .insert("Sec-WebSocket-Protocol", proto.clone());
                        }
                        Ok(res)
                    },
                )
                .await
                .unwrap();
                let _hello = data_ws.next().await.unwrap().unwrap();
                let mut welcome = vec![0u8; 32];
                welcome[0] = 0x81;
                welcome[1..17].copy_from_slice(&[9u8; 16]);
                welcome[24..32].copy_from_slice(&42u64.to_le_bytes());
                data_ws.send(Message::Binary(welcome.into())).await.unwrap();
                data_ws
            });

            let mut wrote = String::new();
            let mut saw_set_theme = false;
            let mut theme_calls = 0;
            let mut take_calls = 0;
            while let Some(Ok(Message::Text(text))) = ctrl_ws.next().await {
                let req: Value = serde_json::from_str(&text).unwrap();
                let id = req["id"].as_str().unwrap_or("");
                let method = req["method"].as_str().unwrap();
                if method == "com.superlogical.terminal.write" {
                    let data = req["payload"]["args"]["data"].as_str().unwrap_or("");
                    wrote.push_str(data);
                    ctrl_ws
                        .send(Message::Text(
                            json!({
                                "type": "response",
                                "id": id,
                                "payload": {"bytes_written": data.len()}
                            })
                            .to_string()
                            .into(),
                        ))
                        .await
                        .unwrap();
                    continue;
                }
                if method == "block.event" {
                    continue;
                }
                let result = match method {
                    "session.bootstrap" => json!({
                        "client_id": "client:1",
                        "selected_session": {
                            "view": {
                                "label": "work",
                                "active_window_id": "window:1",
                                "windows": [{
                                    "window_id": "window:1",
                                    "focused_block_id": "block:1",
                                    "active_layer_id": "layer:1",
                                    "layers": [{
                                        "id": "layer:1",
                                        "focused_block_id": "block:1",
                                        "root": {"type": "block", "block_id": "block:1"}
                                    }]
                                }]
                            }
                        }
                    }),
                    "com.superlogical.terminal.set_theme" => {
                        assert_eq!(req["payload"]["args"]["scheme"], "light");
                        saw_set_theme = true;
                        theme_calls += 1;
                        json!({})
                    }
                    "session.own_block" => {
                        take_calls += 1;
                        json!({})
                    }
                    "com.superlogical.terminal.resize" => json!({}),
                    "data.connect" => json!({
                        "ticket": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 16])
                    }),
                    "com.superlogical.terminal.format" => {
                        assert_ne!(req["payload"]["args"]["extra_palette"], json!(true));
                        json!({"content": "primed-", "id": 7})
                    }
                    "com.superlogical.terminal.blob_read" => {
                        json!({"data": "screen ", "eof": true})
                    }
                    "com.superlogical.terminal.title" => {
                        json!({"title": "vim"})
                    }
                    _ => json!({}),
                };
                ctrl_ws
                    .send(Message::Text(
                        json!({
                            "type": "response",
                            "id": id,
                            "payload": result
                        })
                        .to_string()
                        .into(),
                    ))
                    .await
                    .unwrap();
                if method == "session.detach" {
                    break;
                }
            }
            assert!(saw_set_theme);
            let _data_ws = data_task.await.unwrap();
            (wrote, theme_calls, take_calls)
        });

        let address = format!("http://{addr}").parse().unwrap();
        let (mut ctrl, _events) = Control::connect(&address, None).await.unwrap();
        let theme = Theme {
            foreground: Some("#000000".to_owned()),
            background: Some("#ffffff".to_owned()),
            cursor: None,
            palette: Vec::new(),
            scheme: Some("light".to_owned()),
        };
        let mut attached = Attached::start(
            &mut ctrl,
            "session:1",
            &address,
            BlockSelection::Selectors(None, None),
            (40, 10),
            theme,
        )
        .await
        .unwrap();
        assert_eq!(attached.block_id, "block:1");
        assert!(!attached.primed);

        let mut stream_bytes = snapshot_header();
        stream_bytes.extend_from_slice(b"stale");
        attached.feed(&stream_bytes, &mut ctrl).await.unwrap();
        assert!(attached.primed);

        let live = b"live!\x1b]2;running\x07\x1b_rex1;42;{\"type\":\"resize\",\"cols\":50,\"rows\":12}\x1b\\";
        attached.feed(live, &mut ctrl).await.unwrap();

        let mut out = Vec::new();
        attached.flush(&mut out).unwrap();
        assert_eq!(
            out,
            b"\x1b[2J\x1b[Hprimed-screen \x1b]0;zrex: vim\x07live!\x1b]2;zrex: running\x07"
        );

        let other = attached
            .event(
                "session_destroyed",
                &json!({"session_id": "session:other"}),
                &mut ctrl,
            )
            .await
            .unwrap();
        assert!(other.is_none());

        attached
            .event(
                "block_event",
                &json!({
                    "session_id": "session:1",
                    "block_id": "block:1",
                    "name": "clipboard_written",
                    "payload": {"text": "copied"}
                }),
                &mut ctrl,
            )
            .await
            .unwrap();
        let mut clip_out = Vec::new();
        attached.flush(&mut clip_out).unwrap();
        assert_eq!(clip_out, b"\x1b]52;c;Y29waWVk\x07");

        // The host reported a scheme change: zrex asks it for the colors again
        // and hands the new theme to the block.
        let (host_tx, host_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut host_input = InputReader::from_channel(host_rx);
        host_tx
            .send(
                b"\x1b]10;rgb:1111/1111/1111\x07\x1b]11;rgb:eeee/eeee/eeee\x07\x1b[?62;22c"
                    .to_vec(),
            )
            .unwrap();
        let mut host_out = Vec::new();
        let flow = attached
            .refresh_theme(&mut host_out, &mut host_input, &mut ctrl)
            .await
            .unwrap();
        assert!(matches!(flow, Flow::Continue));
        assert!(host_out.starts_with(b"\x1b]10;?\x07"));
        assert_eq!(attached.theme.background.as_deref(), Some("#eeeeee"));
        assert_eq!(attached.theme.scheme.as_deref(), Some("light"));

        // Another client took the block. The block keeps that client's size
        // and colors until this one is claimed back, so zrex claims nothing.
        let owner = attached
            .event(
                "block_owner_changed",
                &json!({
                    "session_id": "session:1",
                    "block_id": "block:1",
                    "owner": "client:2"
                }),
                &mut ctrl,
            )
            .await
            .unwrap();
        assert!(owner.is_none());
        assert!(!attached.owns);

        // A scheme change while another client owns the block updates the
        // colors zrex holds, but not the block's.
        let (other_tx, other_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut other_input = InputReader::from_channel(other_rx);
        other_tx
            .send(
                b"\x1b]10;rgb:2222/2222/2222\x07\x1b]11;rgb:dddd/dddd/dddd\x07\x1b[?62;22c"
                    .to_vec(),
            )
            .unwrap();
        let mut other_out = Vec::new();
        let flow = attached
            .refresh_theme(&mut other_out, &mut other_input, &mut ctrl)
            .await
            .unwrap();
        assert!(matches!(flow, Flow::Continue));
        assert_eq!(attached.theme.background.as_deref(), Some("#dddddd"));

        // Typing in the terminal claims the block back, with this terminal's
        // size and colors.
        let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut input = InputReader::from_channel(in_rx);
        in_tx.send(b" -l".to_vec()).unwrap();
        in_tx.send(b"a\n".to_vec()).unwrap();
        let flow = attached.burst(b"ls", &mut input, &mut ctrl).await.unwrap();
        assert!(matches!(flow, Flow::Continue));
        assert!(attached.owns);
        finish_write(&mut attached.write_inflight).await.unwrap();
        attached.pump_write(&mut ctrl).unwrap();
        assert!(attached.write_inflight.is_none());

        // The other client gives the block up, so the server hands it to the
        // client in line: this one. It takes this terminal's size and colors
        // again without claiming anything.
        attached
            .event(
                "block_owner_changed",
                &json!({
                    "session_id": "session:1",
                    "block_id": "block:1",
                    "owner": "client:2"
                }),
                &mut ctrl,
            )
            .await
            .unwrap();
        assert!(!attached.owns);
        attached
            .event(
                "block_owner_changed",
                &json!({
                    "session_id": "session:1",
                    "block_id": "block:1",
                    "owner": "client:1"
                }),
                &mut ctrl,
            )
            .await
            .unwrap();
        assert!(attached.owns);

        let detach_flow = attached
            .burst(b"\x1c", &mut input, &mut ctrl)
            .await
            .unwrap();
        assert_eq!(detach_flow, Flow::Detach { double: false });

        let double_same_read = attached
            .burst(b"\x1c\x1c", &mut input, &mut ctrl)
            .await
            .unwrap();
        assert_eq!(double_same_read, Flow::Detach { double: true });

        let (queued_tx, queued_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut queued_input = InputReader::from_channel(queued_rx);
        queued_tx.send(b"\x1b[92;5u".to_vec()).unwrap();
        let double_queued = attached
            .burst(b"\x1c", &mut queued_input, &mut ctrl)
            .await
            .unwrap();
        assert_eq!(double_queued, Flow::Detach { double: true });
        assert!(queued_input.is_empty());

        let block_end = attached
            .event(
                "block_closed",
                &json!({"session_id": "session:1", "block_id": "block:1"}),
                &mut ctrl,
            )
            .await
            .unwrap();
        assert!(matches!(block_end, Some(Ending::Block)));

        let session_end = attached
            .event(
                "session_destroyed",
                &json!({"session_id": "session:1"}),
                &mut ctrl,
            )
            .await
            .unwrap();
        assert!(matches!(session_end, Some(Ending::Session)));

        detach(&mut ctrl, &mut attached).await;
        let (wrote, theme_calls, take_calls) = server.await.unwrap();
        assert_eq!(wrote, "ls -la\n");
        // Attach, a scheme change while owning, the claim on typing, and the
        // block coming back from the other client.
        assert_eq!(theme_calls, 4);
        // Attach and the claim on typing; the other client's claim does not
        // make zrex claim back.
        assert_eq!(take_calls, 2);
    }

    #[test]
    fn chunks_writes_on_utf8_boundaries() {
        let mut queue = "hi🦀ok".to_owned();
        assert_eq!(take_write_chunk(&mut queue, 4), "hi");
        assert_eq!(queue, "🦀ok");
        assert_eq!(take_write_chunk(&mut queue, 2), "🦀");
        assert_eq!(queue, "ok");
        assert_eq!(take_write_chunk(&mut queue, 10), "ok");
        assert!(queue.is_empty());
    }

    #[tokio::test]
    async fn serializes_terminal_writes_and_coalesces_split_bracketed_paste() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (release_first_tx, release_first_rx) = tokio::sync::oneshot::channel::<()>();
        let (saw_first_tx, saw_first_rx) = tokio::sync::oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            let (ctrl_tcp, _) = listener.accept().await.unwrap();
            #[allow(
                clippy::result_large_err,
                reason = "tungstenite fixes the callback error type"
            )]
            let mut ctrl_ws = tokio_tungstenite::accept_hdr_async(
                ctrl_tcp,
                |req: &Request, mut res: Response| {
                    if let Some(proto) = req.headers().get("Sec-WebSocket-Protocol") {
                        res.headers_mut()
                            .insert("Sec-WebSocket-Protocol", proto.clone());
                    }
                    Ok(res)
                },
            )
            .await
            .unwrap();

            let _hello = ctrl_ws.next().await.unwrap().unwrap();
            ctrl_ws
                .send(Message::Text(
                    json!({
                        "type": "welcome",
                        "api_revision": 8,
                        "client": {"reconnect_token": "tok-1"}
                    })
                    .to_string()
                    .into(),
                ))
                .await
                .unwrap();

            let data_task = tokio::spawn(async move {
                let (data_tcp, _) = listener.accept().await.unwrap();
                #[allow(
                    clippy::result_large_err,
                    reason = "tungstenite fixes the callback error type"
                )]
                let mut data_ws = tokio_tungstenite::accept_hdr_async(
                    data_tcp,
                    |req: &Request, mut res: Response| {
                        if let Some(proto) = req.headers().get("Sec-WebSocket-Protocol") {
                            res.headers_mut()
                                .insert("Sec-WebSocket-Protocol", proto.clone());
                        }
                        Ok(res)
                    },
                )
                .await
                .unwrap();
                let _hello = data_ws.next().await.unwrap().unwrap();
                let mut welcome = vec![0u8; 32];
                welcome[0] = 0x81;
                welcome[1..17].copy_from_slice(&[9u8; 16]);
                welcome[24..32].copy_from_slice(&42u64.to_le_bytes());
                data_ws.send(Message::Binary(welcome.into())).await.unwrap();
                data_ws
            });

            let mut writes = Vec::new();
            let mut saw_first_tx = Some(saw_first_tx);
            let mut release_first_rx = Some(release_first_rx);
            while let Some(Ok(Message::Text(text))) = ctrl_ws.next().await {
                let req: Value = serde_json::from_str(&text).unwrap();
                let id = req["id"].as_str().unwrap_or("");
                let method = req["method"].as_str().unwrap();
                if method == "block.event" {
                    continue;
                }
                if method == "com.superlogical.terminal.write" {
                    let data = req["payload"]["args"]["data"]
                        .as_str()
                        .unwrap_or("")
                        .to_owned();
                    writes.push(data.clone());
                    if writes.len() == 1 {
                        if let Some(tx) = saw_first_tx.take() {
                            let _ = tx.send(());
                        }
                        if let Some(rx) = release_first_rx.take() {
                            let _ = rx.await;
                        }
                    }
                    ctrl_ws
                        .send(Message::Text(
                            json!({
                                "type": "response",
                                "id": id,
                                "payload": {"bytes_written": data.len()}
                            })
                            .to_string()
                            .into(),
                        ))
                        .await
                        .unwrap();
                    continue;
                }
                let result = match method {
                    "session.bootstrap" => json!({
                        "client_id": "client:1",
                        "selected_session": {
                            "view": {
                                "label": "work",
                                "active_window_id": "window:1",
                                "windows": [{
                                    "window_id": "window:1",
                                    "focused_block_id": "block:1",
                                    "active_layer_id": "layer:1",
                                    "layers": [{
                                        "id": "layer:1",
                                        "focused_block_id": "block:1",
                                        "root": {"type": "block", "block_id": "block:1"}
                                    }]
                                }]
                            }
                        }
                    }),
                    "data.connect" => json!({
                        "ticket": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 16])
                    }),
                    _ => json!({}),
                };
                ctrl_ws
                    .send(Message::Text(
                        json!({"type": "response", "id": id, "payload": result})
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();
                if method == "session.detach" {
                    break;
                }
            }
            let _data_ws = data_task.await.unwrap();
            writes
        });

        let address = format!("http://{addr}").parse().unwrap();
        let (mut ctrl, _events) = Control::connect(&address, None).await.unwrap();
        let mut attached = Attached::start(
            &mut ctrl,
            "session:1",
            &address,
            BlockSelection::Selectors(None, None),
            (80, 24),
            Theme::default(),
        )
        .await
        .unwrap();

        let (_in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut input = InputReader::from_channel(in_rx);
        // Simulate a terminal like foot emitting bracketed paste across
        // separate reads: ESC[200~, body, ESC[201~.
        attached
            .burst(b"\x1b[200~", &mut input, &mut ctrl)
            .await
            .unwrap();
        saw_first_rx.await.unwrap();
        assert!(attached.write_inflight.is_some());

        // While the first write is still in flight, later chunks must queue
        // locally instead of racing concurrently on the server.
        attached
            .burst(b"pasted text", &mut input, &mut ctrl)
            .await
            .unwrap();
        attached
            .burst(b"\x1b[201~", &mut input, &mut ctrl)
            .await
            .unwrap();
        assert_eq!(attached.write_queue, "pasted text\x1b[201~");

        // Completing the first write flushes the coalesced remainder in order.
        release_first_tx.send(()).unwrap();
        finish_write(&mut attached.write_inflight).await.unwrap();
        attached.pump_write(&mut ctrl).unwrap();
        assert!(attached.write_queue.is_empty());
        assert!(attached.write_inflight.is_some());

        finish_write(&mut attached.write_inflight).await.unwrap();
        attached.pump_write(&mut ctrl).unwrap();
        assert!(attached.write_inflight.is_none());

        detach(&mut ctrl, &mut attached).await;
        let writes = server.await.unwrap();
        assert_eq!(writes, vec!["\x1b[200~", "pasted text\x1b[201~"]);
    }

    #[tokio::test]
    async fn detach_drains_inflight_coalesced_writes_and_batched_prefix_before_detaching() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (release_first_tx, release_first_rx) = tokio::sync::oneshot::channel::<()>();
        let (saw_first_tx, saw_first_rx) = tokio::sync::oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            let (ctrl_tcp, _) = listener.accept().await.unwrap();
            #[allow(
                clippy::result_large_err,
                reason = "tungstenite fixes the callback error type"
            )]
            let mut ctrl_ws = tokio_tungstenite::accept_hdr_async(
                ctrl_tcp,
                |req: &Request, mut res: Response| {
                    if let Some(proto) = req.headers().get("Sec-WebSocket-Protocol") {
                        res.headers_mut()
                            .insert("Sec-WebSocket-Protocol", proto.clone());
                    }
                    Ok(res)
                },
            )
            .await
            .unwrap();

            let _hello = ctrl_ws.next().await.unwrap().unwrap();
            ctrl_ws
                .send(Message::Text(
                    json!({
                        "type": "welcome",
                        "api_revision": 8,
                        "client": {"reconnect_token": "tok-1"}
                    })
                    .to_string()
                    .into(),
                ))
                .await
                .unwrap();

            let data_task = tokio::spawn(async move {
                let (data_tcp, _) = listener.accept().await.unwrap();
                #[allow(
                    clippy::result_large_err,
                    reason = "tungstenite fixes the callback error type"
                )]
                let mut data_ws = tokio_tungstenite::accept_hdr_async(
                    data_tcp,
                    |req: &Request, mut res: Response| {
                        if let Some(proto) = req.headers().get("Sec-WebSocket-Protocol") {
                            res.headers_mut()
                                .insert("Sec-WebSocket-Protocol", proto.clone());
                        }
                        Ok(res)
                    },
                )
                .await
                .unwrap();
                let _hello = data_ws.next().await.unwrap().unwrap();
                let mut welcome = vec![0u8; 32];
                welcome[0] = 0x81;
                welcome[1..17].copy_from_slice(&[9u8; 16]);
                welcome[24..32].copy_from_slice(&42u64.to_le_bytes());
                data_ws.send(Message::Binary(welcome.into())).await.unwrap();
                data_ws
            });

            let mut order = Vec::new();
            let mut saw_first_tx = Some(saw_first_tx);
            let mut release_first_rx = Some(release_first_rx);
            while let Some(Ok(Message::Text(text))) = ctrl_ws.next().await {
                let req: Value = serde_json::from_str(&text).unwrap();
                let id = req["id"].as_str().unwrap_or("");
                let method = req["method"].as_str().unwrap();
                if method == "block.event" {
                    continue;
                }
                if method == "com.superlogical.terminal.write" {
                    let data = req["payload"]["args"]["data"]
                        .as_str()
                        .unwrap_or("")
                        .to_owned();
                    order.push(format!("write:{data}"));
                    if order.len() == 1 {
                        if let Some(tx) = saw_first_tx.take() {
                            let _ = tx.send(());
                        }
                        if let Some(rx) = release_first_rx.take() {
                            let _ = rx.await;
                        }
                    }
                    ctrl_ws
                        .send(Message::Text(
                            json!({
                                "type": "response",
                                "id": id,
                                "payload": {"bytes_written": data.len()}
                            })
                            .to_string()
                            .into(),
                        ))
                        .await
                        .unwrap();
                    continue;
                }
                if method == "session.detach" {
                    order.push("detach".to_owned());
                }
                let result = match method {
                    "session.bootstrap" => json!({
                        "client_id": "client:1",
                        "selected_session": {
                            "view": {
                                "label": "work",
                                "active_window_id": "window:1",
                                "windows": [{
                                    "window_id": "window:1",
                                    "focused_block_id": "block:1",
                                    "active_layer_id": "layer:1",
                                    "layers": [{
                                        "id": "layer:1",
                                        "focused_block_id": "block:1",
                                        "root": {"type": "block", "block_id": "block:1"}
                                    }]
                                }]
                            }
                        }
                    }),
                    "data.connect" => json!({
                        "ticket": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 16])
                    }),
                    _ => json!({}),
                };
                ctrl_ws
                    .send(Message::Text(
                        json!({"type": "response", "id": id, "payload": result})
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();
                if method == "session.detach" {
                    break;
                }
            }
            let _data_ws = data_task.await.unwrap();
            order
        });

        let address = format!("http://{addr}").parse().unwrap();
        let (mut ctrl, _events) = Control::connect(&address, None).await.unwrap();
        let mut attached = Attached::start(
            &mut ctrl,
            "session:1",
            &address,
            BlockSelection::Selectors(None, None),
            (80, 24),
            Theme::default(),
        )
        .await
        .unwrap();

        let (_in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut input = InputReader::from_channel(in_rx);
        attached
            .burst(b"first-", &mut input, &mut ctrl)
            .await
            .unwrap();
        saw_first_rx.await.unwrap();

        // While the first write is in flight, the user types more text batched
        // with Ctrl-\ in the same read.
        let flow = attached
            .burst(b"second\x1b[?\x1cignored", &mut input, &mut ctrl)
            .await
            .unwrap();
        assert_eq!(flow, Flow::Detach { double: false });

        release_first_tx.send(()).unwrap();
        detach(&mut ctrl, &mut attached).await;
        let order = server.await.unwrap();
        assert_eq!(order, vec!["write:first-", "write:second\x1b[?", "detach"]);
    }

    #[tokio::test]
    async fn read_chunks_enforces_deadline_size_cap_and_progress() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    #[allow(
                        clippy::result_large_err,
                        reason = "tungstenite fixes the callback error type"
                    )]
                    let mut ws = tokio_tungstenite::accept_hdr_async(
                        stream,
                        |req: &Request, mut res: Response| {
                            if let Some(proto) = req.headers().get("Sec-WebSocket-Protocol") {
                                res.headers_mut()
                                    .insert("Sec-WebSocket-Protocol", proto.clone());
                            }
                            Ok(res)
                        },
                    )
                    .await
                    .unwrap();
                    let _ = ws.next().await;
                    ws.send(Message::Text(
                        json!({"type": "welcome", "api_revision": 8})
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();

                    while let Some(Ok(Message::Text(text))) = ws.next().await {
                        let req: Value = serde_json::from_str(&text).unwrap();
                        let id = req["id"].as_str().unwrap();
                        let blob_id = req["payload"]["args"]["id"].as_i64().unwrap();
                        let payload = match blob_id {
                            1 => json!({"data": "123456", "eof": false}),
                            2 => json!({"data": "", "eof": false}),
                            3 => {
                                tokio::time::sleep(Duration::from_secs(5)).await;
                                json!({"data": "late", "eof": true})
                            }
                            _ => json!({"data": "ok", "eof": true}),
                        };
                        let _ = ws
                            .send(Message::Text(
                                json!({"type": "response", "id": id, "payload": payload})
                                    .to_string()
                                    .into(),
                            ))
                            .await;
                    }
                });
            }
        });

        let address = format!("http://{addr}").parse().unwrap();
        let (mut ctrl, _events) = Control::connect(&address, None).await.unwrap();
        let block = BlockRef::new("session:1", "block:1");

        // 1. Size cap exceeded.
        let err = read_chunks_with_limits(
            &mut ctrl,
            block,
            "com.superlogical.terminal.blob_read",
            1,
            String::new(),
            tokio::time::Instant::now() + Duration::from_secs(2),
            10,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("maximum size"));

        // 2. Empty non-EOF chunk fails instead of looping forever.
        let err = read_chunks_with_limits(
            &mut ctrl,
            block,
            "com.superlogical.terminal.blob_read",
            2,
            String::new(),
            tokio::time::Instant::now() + Duration::from_secs(2),
            1024,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("empty chunk"));

        // 3. Wedged server hits deadline with CallTimeout, which transient() recognizes.
        let err = read_chunks_with_limits(
            &mut ctrl,
            block,
            "com.superlogical.terminal.blob_read",
            3,
            String::new(),
            tokio::time::Instant::now() + Duration::from_millis(40),
            1024,
        )
        .await
        .unwrap_err();
        assert!(err.downcast_ref::<CallTimeout>().is_some());
        assert!(transient(&ctrl, &err));
    }

    #[test]
    fn detects_write_target_gone_errors() {
        for (code, status) in [
            ("unknown", 404),
            ("not_found", 404),
            ("not_found", 400),
            ("block_not_found", 400),
            ("session_not_found", 400),
            ("block_closed", 410),
        ] {
            let err = anyhow::Error::new(ApiError {
                code: code.to_owned(),
                message: "gone".to_owned(),
                status,
            });
            assert!(write_target_gone(&err), "expected gone for {code} {status}");
        }

        for (code, status) in [("conflict", 409), ("internal", 500), ("forbidden", 403)] {
            let err = anyhow::Error::new(ApiError {
                code: code.to_owned(),
                message: "other".to_owned(),
                status,
            });
            assert!(
                !write_target_gone(&err),
                "expected not gone for {code} {status}"
            );
        }

        assert!(!write_target_gone(&anyhow::anyhow!(
            "the control connection ended"
        )));
        assert!(!write_target_gone(&anyhow::Error::new(StreamClosed {
            code: Some(4000),
            reason: String::new(),
        })));
    }

    #[tokio::test]
    async fn ignores_write_target_gone_until_block_closed_arrives() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (ctrl_tcp, _) = listener.accept().await.unwrap();
            #[allow(
                clippy::result_large_err,
                reason = "tungstenite fixes the callback error type"
            )]
            let mut ctrl_ws = tokio_tungstenite::accept_hdr_async(
                ctrl_tcp,
                |req: &Request, mut res: Response| {
                    if let Some(proto) = req.headers().get("Sec-WebSocket-Protocol") {
                        res.headers_mut()
                            .insert("Sec-WebSocket-Protocol", proto.clone());
                    }
                    Ok(res)
                },
            )
            .await
            .unwrap();

            let _hello = ctrl_ws.next().await.unwrap().unwrap();
            ctrl_ws
                .send(Message::Text(
                    json!({
                        "type": "welcome",
                        "api_revision": 8,
                        "client": {"reconnect_token": "tok-1"}
                    })
                    .to_string()
                    .into(),
                ))
                .await
                .unwrap();

            let data_task = tokio::spawn(async move {
                let (data_tcp, _) = listener.accept().await.unwrap();
                #[allow(
                    clippy::result_large_err,
                    reason = "tungstenite fixes the callback error type"
                )]
                let mut data_ws = tokio_tungstenite::accept_hdr_async(
                    data_tcp,
                    |req: &Request, mut res: Response| {
                        if let Some(proto) = req.headers().get("Sec-WebSocket-Protocol") {
                            res.headers_mut()
                                .insert("Sec-WebSocket-Protocol", proto.clone());
                        }
                        Ok(res)
                    },
                )
                .await
                .unwrap();
                let _hello = data_ws.next().await.unwrap().unwrap();
                let mut welcome = vec![0u8; 32];
                welcome[0] = 0x81;
                welcome[1..17].copy_from_slice(&[9u8; 16]);
                welcome[24..32].copy_from_slice(&42u64.to_le_bytes());
                data_ws.send(Message::Binary(welcome.into())).await.unwrap();
                data_ws
            });

            while let Some(Ok(Message::Text(text))) = ctrl_ws.next().await {
                let req: Value = serde_json::from_str(&text).unwrap();
                let id = req["id"].as_str().unwrap_or("");
                let method = req["method"].as_str().unwrap();
                if method == "block.event" {
                    continue;
                }
                if method == "com.superlogical.terminal.write" {
                    ctrl_ws
                        .send(Message::Text(
                            json!({
                                "type": "response",
                                "id": id,
                                "error": {
                                    "code": "block_not_found",
                                    "message": "block already closed",
                                    "status": 404
                                }
                            })
                            .to_string()
                            .into(),
                        ))
                        .await
                        .unwrap();
                    ctrl_ws
                        .send(Message::Text(
                            json!({
                                "type": "event",
                                "payload": {
                                    "type": "session_event",
                                    "payload": {
                                        "session_id": "session:1",
                                        "event": {
                                            "type": "block_closed",
                                            "payload": {"block_id": "block:1"}
                                        }
                                    }
                                }
                            })
                            .to_string()
                            .into(),
                        ))
                        .await
                        .unwrap();
                    break;
                }
                let result = match method {
                    "session.bootstrap" => json!({
                        "client_id": "client:1",
                        "selected_session": {
                            "view": {
                                "label": "work",
                                "active_window_id": "window:1",
                                "windows": [{
                                    "window_id": "window:1",
                                    "focused_block_id": "block:1",
                                    "active_layer_id": "layer:1",
                                    "layers": [{
                                        "id": "layer:1",
                                        "focused_block_id": "block:1",
                                        "root": {"type": "block", "block_id": "block:1"}
                                    }]
                                }]
                            }
                        }
                    }),
                    "data.connect" => json!({
                        "ticket": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 16])
                    }),
                    _ => json!({}),
                };
                ctrl_ws
                    .send(Message::Text(
                        json!({"type": "response", "id": id, "payload": result})
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();
            }
            let _data_ws = data_task.await.unwrap();
        });

        let address = format!("http://{addr}").parse().unwrap();
        let (mut ctrl, mut events) = Control::connect(&address, None).await.unwrap();
        let mut attached = Attached::start(
            &mut ctrl,
            "session:1",
            &address,
            BlockSelection::Selectors(None, None),
            (80, 24),
            Theme::default(),
        )
        .await
        .unwrap();

        let (_in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut input = InputReader::from_channel(in_rx);
        attached.burst(b"a", &mut input, &mut ctrl).await.unwrap();
        attached.write_queue.push_str("queued");

        let err = finish_write(&mut attached.write_inflight)
            .await
            .unwrap_err();
        assert!(write_target_gone(&err));
        attached.write_queue.clear();
        assert!(attached.write_queue.is_empty());

        let (name, payload) = events.recv().await.unwrap();
        let ending = attached.event(&name, &payload, &mut ctrl).await.unwrap();
        assert!(matches!(ending, Some(Ending::Block)));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn finish_write_times_out_with_call_timeout_and_clears_inflight() {
        let (_tx, rx) = tokio::sync::oneshot::channel::<anyhow::Result<Value>>();
        let mut inflight = Some(InflightWrite {
            rx,
            deadline: tokio::time::Instant::now() + Duration::from_millis(30),
        });
        let err = finish_write(&mut inflight).await.unwrap_err();
        assert!(inflight.is_none());
        assert!(err.downcast_ref::<CallTimeout>().is_some());
    }
}
