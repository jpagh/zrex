use std::cmp::Reverse;
use std::env;
use std::io::{self, Write};

use crossterm::{
    cursor::MoveTo,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute, queue,
    style::{Attribute, Color, Print, SetAttribute, SetForegroundColor},
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use fuzzy_matcher::{FuzzyMatcher, skim::SkimMatcherV2};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use super::{
    ProgramState, SessionChoice, StyleRole, StyledSpan, Target, prefix_to_columns,
    styled_server_row,
};

const MIN_INPUT_WIDTH: usize = 12;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Selection {
    Attach(usize),
    NewSession {
        server_index: usize,
        label: Option<String>,
    },
    NewWindow {
        session_index: usize,
        label: Option<String>,
    },
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Cancel,
    Selected(Selection),
}

#[derive(Debug, PartialEq, Eq)]
enum EditOutcome {
    Changed,
    Moved,
    Unhandled,
}

#[derive(Default)]
struct TextInput {
    chars: Vec<char>,
    cursor: usize,
}

impl TextInput {
    fn text(&self) -> String {
        self.chars.iter().collect()
    }

    fn trimmed_non_empty(&self) -> Option<String> {
        let text = self.text();
        let trimmed = text.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    }

    fn handle_key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> EditOutcome {
        match (code, modifiers) {
            (KeyCode::Char('u'), KeyModifiers::CONTROL) => {
                if self.chars.is_empty() {
                    return EditOutcome::Moved;
                }
                self.chars.clear();
                self.cursor = 0;
                EditOutcome::Changed
            }
            (KeyCode::Backspace, _) if self.cursor > 0 => {
                self.cursor -= 1;
                self.chars.remove(self.cursor);
                EditOutcome::Changed
            }
            (KeyCode::Delete, _) if self.cursor < self.chars.len() => {
                self.chars.remove(self.cursor);
                EditOutcome::Changed
            }
            (KeyCode::Left, KeyModifiers::ALT | KeyModifiers::CONTROL)
            | (KeyCode::Char('b'), KeyModifiers::ALT) => {
                self.cursor = word_left(&self.chars, self.cursor);
                EditOutcome::Moved
            }
            (KeyCode::Right, KeyModifiers::ALT | KeyModifiers::CONTROL)
            | (KeyCode::Char('f'), KeyModifiers::ALT) => {
                self.cursor = word_right(&self.chars, self.cursor);
                EditOutcome::Moved
            }
            (KeyCode::Home, _) | (KeyCode::Char('a'), KeyModifiers::CONTROL) => {
                self.cursor = 0;
                EditOutcome::Moved
            }
            (KeyCode::End, _) | (KeyCode::Char('e'), KeyModifiers::CONTROL) => {
                self.cursor = self.chars.len();
                EditOutcome::Moved
            }
            (KeyCode::Left, _) => {
                self.cursor = self.cursor.saturating_sub(1);
                EditOutcome::Moved
            }
            (KeyCode::Right, _) => {
                self.cursor = (self.cursor + 1).min(self.chars.len());
                EditOutcome::Moved
            }
            (KeyCode::Char(ch), mods)
                if !ch.is_control() && mods.difference(KeyModifiers::SHIFT).is_empty() =>
            {
                self.chars.insert(self.cursor, ch);
                self.cursor += 1;
                EditOutcome::Changed
            }
            _ => EditOutcome::Unhandled,
        }
    }

    fn visible(&self, max_width: usize) -> (String, usize) {
        let mut start = self.cursor;
        let mut offset = 0;
        while start > 0 {
            let next = offset + self.chars[start - 1].width().unwrap_or(0);
            if next > max_width {
                break;
            }
            offset = next;
            start -= 1;
        }
        let mut remaining = max_width;
        let displayed: String = self.chars[start..]
            .iter()
            .copied()
            .take_while(|ch| {
                let width = ch.width().unwrap_or(0);
                if width > remaining {
                    return false;
                }
                remaining -= width;
                true
            })
            .collect();
        (displayed, offset)
    }
}

enum Mode {
    Attach,
    NewSession {
        server_index: usize,
        first: usize,
        input: TextInput,
    },
    NewWindow {
        session_index: usize,
        first: usize,
        input: TextInput,
    },
}

struct PickerState<'a> {
    targets: &'a [Target],
    sessions: &'a [SessionChoice],
    servers: &'a [String],
    labels: Vec<String>,
    matcher: SkimMatcherV2,
    attach_input: TextInput,
    matches: Vec<(usize, Vec<usize>)>,
    attach_selected: usize,
    attach_first: usize,
    mode: Mode,
}

impl<'a> PickerState<'a> {
    fn new(targets: &'a [Target], sessions: &'a [SessionChoice], servers: &'a [String]) -> Self {
        let labels = targets.iter().map(Target::search_text).collect();
        let mut state = Self {
            targets,
            sessions,
            servers,
            labels,
            matcher: SkimMatcherV2::default(),
            attach_input: TextInput::default(),
            matches: Vec::new(),
            attach_selected: 0,
            attach_first: 0,
            mode: Mode::Attach,
        };
        state.recompute_matches();
        state
    }

    fn recompute_matches(&mut self) {
        let pattern = self.attach_input.text();
        let mut ranked: Vec<_> = self
            .labels
            .iter()
            .enumerate()
            .filter_map(|(index, label)| {
                self.matcher
                    .fuzzy_indices(label, &pattern)
                    .map(|(score, indices)| (Reverse(score), index, indices))
            })
            .collect();
        ranked.sort_unstable_by_key(|&(score, index, _)| (score, index));
        self.matches = ranked
            .into_iter()
            .map(|(_, index, indices)| (index, indices))
            .collect();
        self.attach_selected = 0;
        self.attach_first = 0;
    }

    fn default_server_index(&self) -> usize {
        self.matches
            .get(self.attach_selected)
            .map(|&(index, _)| self.targets[index].server_index)
            .unwrap_or(0)
    }

    fn default_session_index(&self) -> usize {
        self.matches
            .get(self.attach_selected)
            .map(|&(index, _)| self.targets[index].session_index)
            .unwrap_or(0)
    }

    fn handle_key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> Option<Outcome> {
        if matches!(
            (code, modifiers),
            (KeyCode::Char('c'), KeyModifiers::CONTROL)
        ) {
            return Some(Outcome::Cancel);
        }
        match &mut self.mode {
            Mode::Attach => match (code, modifiers) {
                (KeyCode::Esc, _) => Some(Outcome::Cancel),
                (KeyCode::Enter, _) if !self.matches.is_empty() => Some(Outcome::Selected(
                    Selection::Attach(self.matches[self.attach_selected].0),
                )),
                (KeyCode::Char('n'), KeyModifiers::CONTROL) if !self.servers.is_empty() => {
                    let server_index = self.default_server_index();
                    self.mode = Mode::NewSession {
                        server_index,
                        first: 0,
                        input: TextInput::default(),
                    };
                    None
                }
                (KeyCode::Char('t'), KeyModifiers::CONTROL) if !self.sessions.is_empty() => {
                    let session_index = self.default_session_index();
                    self.mode = Mode::NewWindow {
                        session_index,
                        first: 0,
                        input: TextInput::default(),
                    };
                    None
                }
                (KeyCode::Up | KeyCode::BackTab, _) if !self.matches.is_empty() => {
                    self.attach_selected =
                        (self.attach_selected + self.matches.len() - 1) % self.matches.len();
                    None
                }
                (KeyCode::Down | KeyCode::Tab, _) if !self.matches.is_empty() => {
                    self.attach_selected = (self.attach_selected + 1) % self.matches.len();
                    None
                }
                _ => {
                    if self.attach_input.handle_key(code, modifiers) == EditOutcome::Changed {
                        self.recompute_matches();
                    }
                    None
                }
            },
            Mode::NewSession {
                server_index,
                input,
                ..
            } => match (code, modifiers) {
                (KeyCode::Esc, _) => {
                    self.mode = Mode::Attach;
                    None
                }
                (KeyCode::Enter, _) => Some(Outcome::Selected(Selection::NewSession {
                    server_index: *server_index,
                    label: input.trimmed_non_empty(),
                })),
                (KeyCode::Char('t'), KeyModifiers::CONTROL) if !self.sessions.is_empty() => {
                    let chosen_server = *server_index;
                    let session_index = self
                        .sessions
                        .iter()
                        .position(|session| session.server_index == chosen_server)
                        .unwrap_or_else(|| self.default_session_index());
                    self.mode = Mode::NewWindow {
                        session_index,
                        first: 0,
                        input: TextInput::default(),
                    };
                    None
                }
                (KeyCode::Up | KeyCode::BackTab, _) if self.servers.len() > 1 => {
                    *server_index = (*server_index + self.servers.len() - 1) % self.servers.len();
                    None
                }
                (KeyCode::Down | KeyCode::Tab, _) if self.servers.len() > 1 => {
                    *server_index = (*server_index + 1) % self.servers.len();
                    None
                }
                _ => {
                    input.handle_key(code, modifiers);
                    None
                }
            },
            Mode::NewWindow {
                session_index,
                input,
                ..
            } => match (code, modifiers) {
                (KeyCode::Esc, _) => {
                    self.mode = Mode::Attach;
                    None
                }
                (KeyCode::Enter, _) => Some(Outcome::Selected(Selection::NewWindow {
                    session_index: *session_index,
                    label: input.trimmed_non_empty(),
                })),
                (KeyCode::Char('n'), KeyModifiers::CONTROL) if !self.servers.is_empty() => {
                    let server_index = self.sessions[*session_index].server_index;
                    self.mode = Mode::NewSession {
                        server_index,
                        first: 0,
                        input: TextInput::default(),
                    };
                    None
                }
                (KeyCode::Up | KeyCode::BackTab, _) if self.sessions.len() > 1 => {
                    *session_index =
                        (*session_index + self.sessions.len() - 1) % self.sessions.len();
                    None
                }
                (KeyCode::Down | KeyCode::Tab, _) if self.sessions.len() > 1 => {
                    *session_index = (*session_index + 1) % self.sessions.len();
                    None
                }
                _ => {
                    input.handle_key(code, modifiers);
                    None
                }
            },
        }
    }

    fn render(
        &mut self,
        out: &mut impl Write,
        columns: u16,
        rows: u16,
        use_color: bool,
    ) -> io::Result<()> {
        let width = usize::from(columns.saturating_sub(1));
        let visible = usize::from(rows.saturating_sub(1)).max(1);
        queue!(out, MoveTo(0, 0), Clear(ClearType::All))?;

        let (prompt, displayed, offset) = match &mut self.mode {
            Mode::Attach => {
                self.attach_first = scroll_first(self.attach_first, self.attach_selected, visible);
                if rows > 1 && width > 2 {
                    if self.targets.is_empty() {
                        let hint = if self.sessions.is_empty() {
                            "No sessions yet — press Ctrl-N to create one"
                        } else {
                            "No open windows — press Ctrl-T for a new window or Ctrl-N for a new session"
                        };
                        queue!(out, MoveTo(0, 1))?;
                        render_hint(out, hint, width - 2)?;
                    } else {
                        for (line, &(index, ref indices)) in self
                            .matches
                            .iter()
                            .skip(self.attach_first)
                            .take(visible)
                            .enumerate()
                        {
                            let active = self.attach_first + line == self.attach_selected;
                            queue!(out, MoveTo(0, (line + 1) as u16))?;
                            let spans = self.targets[index].styled_row(width - 2);
                            render_row(out, &spans, indices, active, use_color)?;
                        }
                    }
                }
                let prompt = if self.sessions.is_empty() {
                    choose_prompt(
                        width,
                        &[
                            "Attach (Ctrl-N new session, Esc)> ",
                            "Attach (^N/Esc)> ",
                            "Attach> ",
                        ],
                    )
                } else {
                    choose_prompt(
                        width,
                        &[
                            "Attach (Ctrl-N session, Ctrl-T window, Esc)> ",
                            "Attach (^N/^T/Esc)> ",
                            "Attach> ",
                        ],
                    )
                };
                let (displayed, offset) = self
                    .attach_input
                    .visible(width.saturating_sub(prompt.width()));
                (prompt.to_owned(), displayed, offset)
            }
            Mode::NewSession {
                server_index,
                first,
                input,
            } => {
                *first = scroll_first(*first, *server_index, visible);
                if rows > 1 && width > 2 {
                    if self.servers.len() > 1 {
                        for (line, server) in
                            self.servers.iter().skip(*first).take(visible).enumerate()
                        {
                            let active = *first + line == *server_index;
                            queue!(out, MoveTo(0, (line + 1) as u16))?;
                            let spans = styled_server_row(server, width - 2);
                            render_row(out, &spans, &[], active, use_color)?;
                        }
                    } else {
                        queue!(out, MoveTo(0, 1))?;
                        render_hint(
                            out,
                            "Type a session name, or press Enter for a default name",
                            width - 2,
                        )?;
                    }
                }
                let server = &self.servers[*server_index];
                let prompt = if self.servers.len() > 1 {
                    let full = format!("New session name on [{server}] (Tab: server, Esc: back)> ");
                    let medium = format!("New session on [{server}] (Tab)> ");
                    let short = format!("New session on [{server}]> ");
                    choose_prompt(width, &[&full, &medium, &short, "New session> "]).to_owned()
                } else {
                    let full =
                        format!("New session name on [{server}] (Enter: default, Esc: back)> ");
                    let medium = format!("New session name on [{server}]> ");
                    choose_prompt(
                        width,
                        &[&full, &medium, "New session name> ", "New session> "],
                    )
                    .to_owned()
                };
                let (displayed, offset) = input.visible(width.saturating_sub(prompt.width()));
                (prompt, displayed, offset)
            }
            Mode::NewWindow {
                session_index,
                first,
                input,
            } => {
                *first = scroll_first(*first, *session_index, visible);
                if rows > 1 && width > 2 {
                    if self.sessions.len() > 1 {
                        for (line, session) in
                            self.sessions.iter().skip(*first).take(visible).enumerate()
                        {
                            let active = *first + line == *session_index;
                            queue!(out, MoveTo(0, (line + 1) as u16))?;
                            let spans = session.styled_row(width - 2);
                            render_row(out, &spans, &[], active, use_color)?;
                        }
                    } else {
                        queue!(out, MoveTo(0, 1))?;
                        render_hint(
                            out,
                            "Type a window name, or press Enter for a default name",
                            width - 2,
                        )?;
                    }
                }
                let session = self.sessions[*session_index].display_name();
                let prompt = if self.sessions.len() > 1 {
                    let full = format!("New window name in {session} (Tab: session, Esc: back)> ");
                    let medium = format!("New window in {session} (Tab)> ");
                    let short = format!("New window in {session}> ");
                    choose_prompt(width, &[&full, &medium, &short, "New window> "]).to_owned()
                } else {
                    let full =
                        format!("New window name in {session} (Enter: default, Esc: back)> ");
                    let medium = format!("New window name in {session}> ");
                    choose_prompt(
                        width,
                        &[&full, &medium, "New window name> ", "New window> "],
                    )
                    .to_owned()
                };
                let (displayed, offset) = input.visible(width.saturating_sub(prompt.width()));
                (prompt, displayed, offset)
            }
        };

        queue!(out, MoveTo(0, 0))?;
        render_prompt(out, &prompt, &displayed, use_color)?;
        queue!(out, MoveTo((prompt.width() + offset) as u16, 0))?;
        out.flush()
    }
}

fn scroll_first(first: usize, selected: usize, visible: usize) -> usize {
    first
        .min(selected)
        .max((selected + 1).saturating_sub(visible))
}

fn choose_prompt<'a>(width: usize, candidates: &[&'a str]) -> &'a str {
    for candidate in candidates {
        if width >= candidate.width() + MIN_INPUT_WIDTH {
            return candidate;
        }
    }
    if width > 2 { "> " } else { "" }
}

struct Screen;

impl Drop for Screen {
    fn drop(&mut self) {
        let _ = execute!(
            io::stdout(),
            SetAttribute(Attribute::Reset),
            LeaveAlternateScreen
        );
        let _ = terminal::disable_raw_mode();
    }
}

fn color_enabled() -> bool {
    env::var_os("NO_COLOR").is_none_or(|value| value.is_empty())
}

pub(super) fn select(
    targets: &[Target],
    sessions: &[SessionChoice],
    servers: &[String],
) -> io::Result<Option<Selection>> {
    terminal::enable_raw_mode()?;
    let _screen = Screen;
    let mut out = io::stdout();
    execute!(out, EnterAlternateScreen)?;
    let use_color = color_enabled();
    let mut state = PickerState::new(targets, sessions, servers);
    loop {
        let (columns, rows) = terminal::size()?;
        state.render(&mut out, columns, rows, use_color)?;

        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }
        match state.handle_key(key.code, key.modifiers) {
            Some(Outcome::Cancel) => return Ok(None),
            Some(Outcome::Selected(selection)) => return Ok(Some(selection)),
            None => {}
        }
    }
}

fn render_prompt(
    out: &mut impl Write,
    prompt: &str,
    query: &str,
    use_color: bool,
) -> io::Result<()> {
    if !prompt.is_empty() {
        if use_color {
            queue!(out, SetForegroundColor(Color::DarkCyan))?;
        }
        queue!(
            out,
            SetAttribute(Attribute::Bold),
            Print(prompt),
            SetAttribute(Attribute::Reset)
        )?;
    }
    queue!(out, Print(query))
}

fn render_hint(out: &mut impl Write, text: &str, max_width: usize) -> io::Result<()> {
    let visible = if text.width() <= max_width {
        text.to_owned()
    } else {
        let ellipsis_width = '…'.width().unwrap_or(1);
        format!(
            "{}…",
            prefix_to_columns(text, max_width.saturating_sub(ellipsis_width))
        )
    };
    queue!(
        out,
        Print("  "),
        SetAttribute(Attribute::Dim),
        Print(visible),
        SetAttribute(Attribute::Reset)
    )
}

fn render_row(
    out: &mut impl Write,
    spans: &[StyledSpan],
    match_indices: &[usize],
    active: bool,
    use_color: bool,
) -> io::Result<()> {
    if active {
        if use_color {
            queue!(out, SetForegroundColor(Color::DarkCyan))?;
        }
        queue!(
            out,
            SetAttribute(Attribute::Bold),
            Print("> "),
            SetAttribute(Attribute::Reset)
        )?;
    } else {
        queue!(out, Print("  "))?;
    }

    for span in spans {
        let mut run = String::new();
        let mut run_matched = None;
        for (char_index, ch) in span.text.chars().enumerate() {
            let matched = !match_indices.is_empty()
                && span
                    .search_offset
                    .is_some_and(|base| match_indices.binary_search(&(base + char_index)).is_ok());
            if run_matched == Some(matched) {
                run.push(ch);
            } else {
                if let Some(prev_matched) = run_matched {
                    render_run(out, &run, span.role, prev_matched, active, use_color)?;
                    run.clear();
                }
                run.push(ch);
                run_matched = Some(matched);
            }
        }
        if let Some(prev_matched) = run_matched {
            render_run(out, &run, span.role, prev_matched, active, use_color)?;
        }
    }
    queue!(out, SetAttribute(Attribute::Reset))
}

fn render_run(
    out: &mut impl Write,
    text: &str,
    role: StyleRole,
    matched: bool,
    active: bool,
    use_color: bool,
) -> io::Result<()> {
    queue!(out, SetAttribute(Attribute::Reset))?;
    if active {
        queue!(out, SetAttribute(Attribute::Reverse))?;
    }
    if use_color && let Some(color) = foreground_color(role, matched) {
        queue!(out, SetForegroundColor(color))?;
    }
    if matched {
        queue!(
            out,
            SetAttribute(Attribute::Bold),
            SetAttribute(Attribute::Underlined)
        )?;
    } else if active {
        if matches!(
            role,
            StyleRole::Label | StyleRole::Status(ProgramState::Blocked | ProgramState::Error)
        ) {
            queue!(out, SetAttribute(Attribute::Bold))?;
        }
    } else {
        match role {
            StyleRole::Separator | StyleRole::Title | StyleRole::Status(ProgramState::Idle) => {
                queue!(out, SetAttribute(Attribute::Dim))?;
            }
            StyleRole::Status(ProgramState::Blocked | ProgramState::Error) => {
                queue!(out, SetAttribute(Attribute::Bold))?;
            }
            StyleRole::Server
            | StyleRole::Label
            | StyleRole::Status(ProgramState::Working | ProgramState::Done) => {}
        }
    }
    queue!(out, Print(text))
}

// Use the standard 8 ANSI palette colors (Dark*) so contrast adapts cleanly
// across both dark and light terminal themes.
fn foreground_color(role: StyleRole, matched: bool) -> Option<Color> {
    if matched {
        return Some(Color::DarkYellow);
    }
    match role {
        StyleRole::Server => Some(Color::DarkCyan),
        StyleRole::Label | StyleRole::Separator | StyleRole::Title => None,
        StyleRole::Status(ProgramState::Blocked) => Some(Color::DarkYellow),
        StyleRole::Status(ProgramState::Error) => Some(Color::DarkRed),
        StyleRole::Status(ProgramState::Working) => Some(Color::DarkCyan),
        StyleRole::Status(ProgramState::Done) => Some(Color::DarkGreen),
        StyleRole::Status(ProgramState::Idle) => None,
    }
}

fn word_left(query: &[char], cursor: usize) -> usize {
    cursor - word_distance(query[..cursor].iter().rev())
}

fn word_right(query: &[char], cursor: usize) -> usize {
    cursor + word_distance(query[cursor..].iter())
}

fn word_distance<'a>(chars: impl Iterator<Item = &'a char>) -> usize {
    let mut chars = chars.peekable();
    let mut distance = 0;
    while chars.next_if(|ch| !ch.is_alphanumeric()).is_some() {
        distance += 1;
    }
    while chars.next_if(|ch| ch.is_alphanumeric()).is_some() {
        distance += 1;
    }
    distance
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::picker::test_target;

    fn chars(text: &str) -> Vec<char> {
        text.chars().collect()
    }

    fn type_text(state: &mut PickerState<'_>, text: &str) {
        for ch in text.chars() {
            assert_eq!(
                state.handle_key(KeyCode::Char(ch), KeyModifiers::NONE),
                None
            );
        }
    }

    fn sample_fixture() -> (Vec<Target>, Vec<SessionChoice>, Vec<String>) {
        let servers = vec!["local".to_owned(), "office".to_owned()];
        let sessions = vec![
            SessionChoice {
                server_index: 0,
                server_name: "local".to_owned(),
                session_id: "session:1".to_owned(),
                label: "work".to_owned(),
            },
            SessionChoice {
                server_index: 1,
                server_name: "office".to_owned(),
                session_id: "session:2".to_owned(),
                label: "api".to_owned(),
            },
        ];
        let targets = vec![
            test_target(0, 0, "[local] work / 1 zsh", "session:1", "block:1"),
            test_target(1, 1, "[office] api / 1 nvim", "session:2", "block:2"),
        ];
        (targets, sessions, servers)
    }

    #[test]
    fn word_navigation_moves_across_delimiters_and_words() {
        let query = chars("  office / dev-1  ");
        assert_eq!(word_left(&query, 0), 0);
        assert_eq!(word_left(&query, query.len()), 15);
        assert_eq!(word_left(&query, 15), 11);
        assert_eq!(word_left(&query, 11), 2);
        assert_eq!(word_left(&query, 2), 0);

        assert_eq!(word_right(&query, 0), 8);
        assert_eq!(word_right(&query, 8), 14);
        assert_eq!(word_right(&query, 14), 16);
        assert_eq!(word_right(&query, 16), query.len());
        assert_eq!(word_right(&query, query.len()), query.len());
    }

    #[test]
    fn word_navigation_handles_empty_and_unicode_queries() {
        let empty = chars("");
        assert_eq!(word_left(&empty, 0), 0);
        assert_eq!(word_right(&empty, 0), 0);

        let unicode = chars("π-αβ");
        assert_eq!(word_right(&unicode, 0), 1);
        assert_eq!(word_right(&unicode, 1), 4);
        assert_eq!(word_left(&unicode, 4), 2);
        assert_eq!(word_left(&unicode, 2), 0);
    }

    #[test]
    fn render_row_applies_semantic_colors_match_highlights_and_no_color() {
        let spans = vec![
            StyledSpan {
                role: StyleRole::Server,
                text: "[local]".to_owned(),
                search_offset: Some(0),
            },
            StyledSpan {
                role: StyleRole::Label,
                text: " work".to_owned(),
                search_offset: Some(7),
            },
            StyledSpan {
                role: StyleRole::Separator,
                text: " · ".to_owned(),
                search_offset: Some(12),
            },
            StyledSpan {
                role: StyleRole::Status(ProgramState::Error),
                text: "error build".to_owned(),
                search_offset: Some(15),
            },
        ];

        let mut colored = Vec::new();
        render_row(&mut colored, &spans, &[8, 9], false, true).unwrap();
        let colored = String::from_utf8(colored).unwrap();
        // Server cyan (ANSI 6), matched "wo" yellow+bold+underline (ANSI 3), error red (ANSI 1).
        assert!(colored.contains("\x1b[38;5;6m") || colored.contains("\x1b[36m"));
        assert!(colored.contains("\x1b[38;5;3m") || colored.contains("\x1b[33m"));
        assert!(colored.contains("\x1b[38;5;1m") || colored.contains("\x1b[31m"));
        assert!(colored.contains("\x1b[4m"));
        assert!(colored.contains("wo"));
        assert!(colored.contains("rk"));
        assert!(colored.ends_with("\x1b[0m"));

        let mut active_plain = Vec::new();
        render_row(&mut active_plain, &spans, &[8, 9], true, false).unwrap();
        let active_plain = String::from_utf8(active_plain).unwrap();
        // NO_COLOR mode emits no foreground color escapes, but keeps reverse, bold, and underline.
        assert!(!active_plain.contains("\x1b[38;"));
        assert!(!active_plain.contains("\x1b[31m"));
        assert!(!active_plain.contains("\x1b[33m"));
        assert!(!active_plain.contains("\x1b[36m"));
        assert!(active_plain.contains("\x1b[7m"));
        assert!(active_plain.contains("\x1b[4m"));
        assert!(active_plain.contains("> "));
    }

    #[test]
    fn ctrl_n_creates_new_session_with_default_or_custom_label_and_server_choice() {
        let (targets, sessions, servers) = sample_fixture();
        let mut state = PickerState::new(&targets, &sessions, &servers);

        // Highlight [office] api, then press Ctrl-N: office (index 1) is pre-selected.
        assert_eq!(state.handle_key(KeyCode::Down, KeyModifiers::NONE), None);
        assert_eq!(
            state.handle_key(KeyCode::Char('n'), KeyModifiers::CONTROL),
            None
        );
        // Tab wraps to local (index 0); type a name with surrounding spaces.
        assert_eq!(state.handle_key(KeyCode::Tab, KeyModifiers::NONE), None);
        type_text(&mut state, "  scratch  ");
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::NewSession {
                server_index: 0,
                label: Some("scratch".to_owned()),
            }))
        );

        // Blank or whitespace-only name produces None (default Rex label).
        let mut state = PickerState::new(&targets, &sessions, &servers);
        assert_eq!(state.handle_key(KeyCode::Down, KeyModifiers::NONE), None);
        assert_eq!(
            state.handle_key(KeyCode::Char('n'), KeyModifiers::CONTROL),
            None
        );
        type_text(&mut state, "   ");
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::NewSession {
                server_index: 1,
                label: None,
            }))
        );
    }

    #[test]
    fn ctrl_t_creates_new_window_in_highlighted_or_cycled_session() {
        let (targets, sessions, servers) = sample_fixture();
        let mut state = PickerState::new(&targets, &sessions, &servers);

        // Highlight [office] api, then press Ctrl-T: session 1 is pre-selected.
        assert_eq!(state.handle_key(KeyCode::Down, KeyModifiers::NONE), None);
        assert_eq!(
            state.handle_key(KeyCode::Char('t'), KeyModifiers::CONTROL),
            None
        );
        type_text(&mut state, "logs");
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::NewWindow {
                session_index: 1,
                label: Some("logs".to_owned()),
            }))
        );

        // Can cycle to another session and submit empty name for default label.
        let mut state = PickerState::new(&targets, &sessions, &servers);
        assert_eq!(
            state.handle_key(KeyCode::Char('t'), KeyModifiers::CONTROL),
            None
        );
        assert_eq!(state.handle_key(KeyCode::Down, KeyModifiers::NONE), None);
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::NewWindow {
                session_index: 1,
                label: None,
            }))
        );
    }

    #[test]
    fn esc_returns_to_attach_preserving_query_and_ctrl_c_cancels_from_any_mode() {
        let (targets, sessions, servers) = sample_fixture();
        let mut state = PickerState::new(&targets, &sessions, &servers);

        type_text(&mut state, "api");
        assert_eq!(
            state.handle_key(KeyCode::Char('n'), KeyModifiers::CONTROL),
            None
        );
        type_text(&mut state, "temp");
        // Esc backs out to Attach without cancelling the picker.
        assert_eq!(state.handle_key(KeyCode::Esc, KeyModifiers::NONE), None);
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::Attach(1)))
        );

        // Ctrl-C cancels immediately even inside NewWindow mode.
        assert_eq!(
            state.handle_key(KeyCode::Char('t'), KeyModifiers::CONTROL),
            None
        );
        assert_eq!(
            state.handle_key(KeyCode::Char('c'), KeyModifiers::CONTROL),
            Some(Outcome::Cancel)
        );
    }

    #[test]
    fn empty_server_allows_ctrl_n_and_ignores_ctrl_t() {
        let servers = vec!["local".to_owned()];
        let mut state = PickerState::new(&[], &[], &servers);

        // Ctrl-T is ignored when there are no sessions.
        assert_eq!(
            state.handle_key(KeyCode::Char('t'), KeyModifiers::CONTROL),
            None
        );
        assert!(matches!(state.mode, Mode::Attach));

        // Render empty state cleanly.
        let mut buf = Vec::new();
        state.render(&mut buf, 80, 10, false).unwrap();
        let screen = String::from_utf8(buf).unwrap();
        assert!(screen.contains("No sessions yet"));
        assert!(screen.contains("Ctrl-N"));

        // Ctrl-N creates a session on the sole reachable server.
        assert_eq!(
            state.handle_key(KeyCode::Char('n'), KeyModifiers::CONTROL),
            None
        );
        type_text(&mut state, "dev");
        let mut new_buf = Vec::new();
        state.render(&mut new_buf, 80, 10, false).unwrap();
        let new_screen = String::from_utf8(new_buf).unwrap();
        assert!(new_screen.contains("New session name on [local]"));
        assert!(new_screen.contains("dev"));

        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::NewSession {
                server_index: 0,
                label: Some("dev".to_owned()),
            }))
        );
    }

    #[test]
    fn switching_between_new_session_and_new_window_preserves_context() {
        let (targets, sessions, servers) = sample_fixture();
        let mut state = PickerState::new(&targets, &sessions, &servers);

        // Open NewSession on local (index 0), move to office (index 1), then press Ctrl-T.
        assert_eq!(
            state.handle_key(KeyCode::Char('n'), KeyModifiers::CONTROL),
            None
        );
        assert_eq!(state.handle_key(KeyCode::Down, KeyModifiers::NONE), None);
        assert_eq!(
            state.handle_key(KeyCode::Char('t'), KeyModifiers::CONTROL),
            None
        );
        // Should land on office's session (index 1).
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::NewWindow {
                session_index: 1,
                label: None,
            }))
        );
    }

    #[test]
    fn renders_multi_server_and_multi_session_prompts_including_narrow_and_unicode() {
        let servers = vec!["local".to_owned(), "日本語サーバー".to_owned()];
        let sessions = vec![
            SessionChoice {
                server_index: 0,
                server_name: "local".to_owned(),
                session_id: "session:1".to_owned(),
                label: "work".to_owned(),
            },
            SessionChoice {
                server_index: 1,
                server_name: "日本語サーバー".to_owned(),
                session_id: "session:2".to_owned(),
                label: "開発セッション".to_owned(),
            },
        ];
        let targets = vec![
            test_target(0, 0, "[local] work / 1 zsh", "session:1", "block:1"),
            test_target(
                1,
                1,
                "[日本語サーバー] 開発セッション / 1 zsh",
                "session:2",
                "block:2",
            ),
        ];
        let mut state = PickerState::new(&targets, &sessions, &servers);

        assert_eq!(
            state.handle_key(KeyCode::Char('n'), KeyModifiers::CONTROL),
            None
        );
        for (cols, rows) in [(100, 10), (40, 5), (10, 3), (3, 2), (1, 1)] {
            let mut buf = Vec::new();
            state.render(&mut buf, cols, rows, true).unwrap();
            let output = String::from_utf8(buf).unwrap();
            if cols >= 100 {
                assert!(output.contains("[local]"));
                assert!(output.contains("[日本語サーバー]"));
            }
        }

        assert_eq!(
            state.handle_key(KeyCode::Char('t'), KeyModifiers::CONTROL),
            None
        );
        for (cols, rows) in [(100, 10), (40, 5), (10, 3), (3, 2), (1, 1)] {
            let mut buf = Vec::new();
            state.render(&mut buf, cols, rows, false).unwrap();
            let output = String::from_utf8(buf).unwrap();
            if cols >= 100 {
                assert!(output.contains("[local]"));
                assert!(output.contains("開発セッション"));
            }
        }
    }
}
