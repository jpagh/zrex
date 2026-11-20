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

use super::{ProgramState, StyleRole, StyledSpan, Target};

const PROMPT: &str = "Attach (Esc to cancel)> ";

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

pub(super) fn select(targets: &[&Target]) -> io::Result<Option<usize>> {
    terminal::enable_raw_mode()?;
    let _screen = Screen;
    let mut out = io::stdout();
    execute!(out, EnterAlternateScreen)?;
    let use_color = color_enabled();
    let matcher = SkimMatcherV2::default();
    let labels: Vec<_> = targets.iter().map(|target| target.search_text()).collect();
    let mut query = Vec::<char>::new();
    let mut cursor = 0;
    let mut selected: usize = 0;
    let mut first: usize = 0;
    loop {
        let pattern: String = query.iter().collect();
        let mut matches: Vec<_> = labels
            .iter()
            .enumerate()
            .filter_map(|(index, label)| {
                matcher
                    .fuzzy_indices(label, &pattern)
                    .map(|(score, indices)| (std::cmp::Reverse(score), index, indices))
            })
            .collect();
        matches.sort_unstable_by_key(|&(score, index, _)| (score, index));

        let (columns, rows) = terminal::size()?;
        let width = usize::from(columns.saturating_sub(1));
        let visible = usize::from(rows.saturating_sub(1)).max(1);
        first = first
            .min(selected)
            .max((selected + 1).saturating_sub(visible));
        queue!(out, MoveTo(0, 0), Clear(ClearType::All))?;
        if rows > 1 && width > 2 {
            for (line, &(_, index, ref indices)) in
                matches.iter().skip(first).take(visible).enumerate()
            {
                let active = first + line == selected;
                queue!(out, MoveTo(0, (line + 1) as u16))?;
                let spans = targets[index].styled_row(width - 2);
                render_row(&mut out, &spans, indices, active, use_color)?;
            }
        }
        let prompt = if width > PROMPT.len() {
            PROMPT
        } else if width > 2 {
            "> "
        } else {
            ""
        };
        let query_width = width - prompt.len();
        let mut start = cursor;
        let mut offset = 0;
        while start > 0 {
            let next = offset + query[start - 1].width().unwrap_or(0);
            if next > query_width {
                break;
            }
            offset = next;
            start -= 1;
        }
        let mut remaining = query_width;
        let displayed: String = query[start..]
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
        queue!(out, MoveTo(0, 0))?;
        render_prompt(&mut out, prompt, &displayed, use_color)?;
        queue!(out, MoveTo((prompt.width() + offset) as u16, 0))?;
        out.flush()?;

        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }
        let edited = match (key.code, key.modifiers) {
            (KeyCode::Esc, _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => return Ok(None),
            (KeyCode::Enter, _) if !matches.is_empty() => return Ok(Some(matches[selected].1)),
            (KeyCode::Char('u'), KeyModifiers::CONTROL) => {
                query.clear();
                cursor = 0;
                true
            }
            (KeyCode::Backspace, _) if cursor > 0 => {
                cursor -= 1;
                query.remove(cursor);
                true
            }
            (KeyCode::Delete, _) if cursor < query.len() => {
                query.remove(cursor);
                true
            }
            (KeyCode::Left, KeyModifiers::ALT | KeyModifiers::CONTROL)
            | (KeyCode::Char('b'), KeyModifiers::ALT) => {
                cursor = word_left(&query, cursor);
                false
            }
            (KeyCode::Right, KeyModifiers::ALT | KeyModifiers::CONTROL)
            | (KeyCode::Char('f'), KeyModifiers::ALT) => {
                cursor = word_right(&query, cursor);
                false
            }
            (KeyCode::Home, _) | (KeyCode::Char('a'), KeyModifiers::CONTROL) => {
                cursor = 0;
                false
            }
            (KeyCode::End, _) | (KeyCode::Char('e'), KeyModifiers::CONTROL) => {
                cursor = query.len();
                false
            }
            (KeyCode::Left, _) => {
                cursor = cursor.saturating_sub(1);
                false
            }
            (KeyCode::Right, _) => {
                cursor = (cursor + 1).min(query.len());
                false
            }
            (KeyCode::Up | KeyCode::BackTab, _) if !matches.is_empty() => {
                selected = (selected + matches.len() - 1) % matches.len();
                false
            }
            (KeyCode::Down | KeyCode::Tab, _) if !matches.is_empty() => {
                selected = (selected + 1) % matches.len();
                false
            }
            (KeyCode::Char(ch), mods)
                if !ch.is_control() && mods.difference(KeyModifiers::SHIFT).is_empty() =>
            {
                query.insert(cursor, ch);
                cursor += 1;
                true
            }
            _ => false,
        };
        if edited {
            selected = 0;
            first = 0;
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

    fn chars(text: &str) -> Vec<char> {
        text.chars().collect()
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
}
