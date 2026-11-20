use std::io::{self, Write};

use crossterm::{
    cursor::MoveTo,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute, queue,
    style::{Attribute, Print, SetAttribute},
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use fuzzy_matcher::{FuzzyMatcher, skim::SkimMatcherV2};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use super::Target;

const PROMPT: &str = "Attach (Esc to cancel)> ";

struct Screen;

impl Drop for Screen {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
    }
}

pub(super) fn select(targets: &[&Target]) -> io::Result<Option<usize>> {
    terminal::enable_raw_mode()?;
    let _screen = Screen;
    let mut out = io::stdout();
    execute!(out, EnterAlternateScreen)?;
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
                    .fuzzy_match(label, &pattern)
                    .map(|score| (std::cmp::Reverse(score), index))
            })
            .collect();
        matches.sort_unstable();

        let (columns, rows) = terminal::size()?;
        let width = usize::from(columns.saturating_sub(1));
        let visible = usize::from(rows.saturating_sub(1)).max(1);
        first = first
            .min(selected)
            .max((selected + 1).saturating_sub(visible));
        queue!(out, MoveTo(0, 0), Clear(ClearType::All))?;
        if rows > 1 && width > 2 {
            for (line, &(_, index)) in matches.iter().skip(first).take(visible).enumerate() {
                let active = first + line == selected;
                queue!(
                    out,
                    MoveTo(0, (line + 1) as u16),
                    Print(if active { "> " } else { "  " })
                )?;
                if active {
                    queue!(out, SetAttribute(Attribute::Reverse))?;
                }
                queue!(out, Print(targets[index].row(width - 2)))?;
                if active {
                    queue!(out, SetAttribute(Attribute::Reset))?;
                }
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
        queue!(
            out,
            MoveTo(0, 0),
            Print(prompt),
            Print(displayed),
            MoveTo((prompt.width() + offset) as u16, 0)
        )?;
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
}
