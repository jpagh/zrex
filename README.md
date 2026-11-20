# zrex

A lightweight command-line client for a [Rex](https://www.superlogical.com/rex/docs) server.

`zrex` attaches your terminal to one block of a Rex session in the pass-through style of [`zmx`](https://zmx.sh): no local tab bar, no split borders, no alternate-screen hijacking, and no client-side terminal re-rendering. Rex keeps your sessions, windows, layouts, and blocks running on the server; `zrex` rehydrates the block's scrollback and screen on attach and streams raw VT input and output directly through your terminal.

## Features

- **Session management**: List, create, attach to, and destroy sessions by label, full ID, or 4+ character ID suffix.
- **Attach picker**: Fuzzy-search existing sessions, windows, and splits across saved Rex servers.
- **Window and split selection**: List windows and split panes (`1.1`, `1.2`, ...), attach to any window or split with `--window` (`-w`) and `--block` (`-b`), or create new windows on demand without changing the active window shown in Rex.app.
- **Direct terminal pass-through**: Runs in your terminal's normal screen buffer so native scrollback, native mouse text selection, clickable URLs, Kitty graphics, and OSC escape sequences work directly without an intermediate renderer.
- **Full state rehydration**: Restores scrollback history, cursor state, colors, and terminal modes from the server on attach, and resets terminal modes cleanly on detach.
- **Automatic reconnection**: Reconnects when the network drops and resumes the terminal stream from the last received byte.

## Requirements

- Rust (`cargo`). A Nix flake (`nix develop`) is also available.
- A Rex server reachable over HTTP, HTTPS, or a Unix socket.

## Build

```sh
cargo build --release
```

## Usage

```sh
# Fuzzy-pick an existing session, window, or split
zrex pick

# List sessions, windows, split blocks, and terminal titles
zrex -S https://server.example ls

# Attach to a session (creates it if no session matches)
zrex -S https://server.example a work

# Attach to a specific window by number or label
zrex -S https://server.example a work --window 2
zrex -S https://server.example a work --window build

# Attach to a specific split block inside a window
zrex -S https://server.example a work --window 1.2
zrex -S https://server.example a work --window 1 --block 2
zrex -S https://server.example a work --block 2

# Create a new window with a server-chosen label and attach to it
zrex -S https://server.example a work -w -

# Destroy a session
zrex -S https://server.example kill work
```

### Server Address

The server address is read from `--server` (`-S`), then `REX_SERVER`. Without either, `zrex` uses a local Rex server's Unix socket when one is running, and otherwise defaults to `http://127.0.0.1:7297`. An address may be an HTTP(S) URL or a Unix socket address such as `unix:///Users/you/Library/Application%20Support/rex/server.sock`. An address without a port uses the scheme's default port: 80 for HTTP, 443 for HTTPS.

To reach a Rex server on another machine over Tailscale, use the HTTPS address that `rex server status` reports (for example `https://my-mac.tail1234.ts.net`). The Tailscale node serves HTTPS on port 443, so a bare IP with no port falls back to HTTP on port 80 and is refused.

### Attach Picker

Run `zrex pick`, type to filter, and use the arrow keys (or `Tab`/`Shift-Tab`) and Enter to attach in the same terminal. `Ctrl-U` clears the entire search query, and `Esc` or `Ctrl-C` cancels. `Ctrl-\` detaches straight back to your shell. The picker never creates a session or window.

Use `Alt/Option-←` and `Alt/Option-→` to move by word. `Ctrl-←`/`Ctrl-→` and `Alt-B`/`Alt-F` also work, depending on what your terminal sends. `Home`/`End` or `Ctrl-A`/`Ctrl-E` go to the start or end of the query.

Alongside the window and split labels, the picker shows the terminal title and OSC 7501 program status when Rex has them. You can search the displayed text, for example `blocked` or an agent name. If a pane reports multiple statuses, the picker shows the one that most needs attention. Titles and statuses are fetched when the picker opens.

To search multiple servers, save their names and addresses in `~/.config/zrex/config.toml` (or `$XDG_CONFIG_HOME/zrex/config.toml`):

```toml
[servers]
office = "https://office.example.com"
lab = "https://lab.example.com"
```

Each choice shows its server name. `zrex pick` searches the saved servers alongside the local server (or `REX_SERVER`, if set). Servers are queried in parallel with a short timeout, so an unreachable server doesn't prevent you from picking from another one. Use `zrex -S ADDRESS pick` to search just one server without reading the config file.

### Selecting Sessions, Windows, and Blocks

- **`SESSION`**: Matches a session label, full ID, or the last 4+ characters of an ID. On `attach` (`a`), if no session matches, `zrex` creates a new session with that label. If omitted, `zrex` attaches to the first session on the server.
- **`--window` (`-w`)**: Selects a window by its 1-based number from `zrex ls`, its `window.block` index (such as `1.2`), its label, or `-` for a new window with a default Rex label. Passing a label that no window has creates a new window with that label and one shell block.
- **`--block` (`-b`)**: Selects a block within the target (or active) window by its 1-based number, label, full ID, or 4+ character ID suffix.

`ls` prints each window's label and, beside it, the terminal title its focused block reports — the same title Rex.app shows on the tab.

### Shell Completion

`zrex completion` prints a script that completes session labels, window numbers and labels, and block numbers and labels from the live server.

```sh
# zsh (after compinit, in ~/.zshrc)
source <(zrex completion zsh)

# bash (in ~/.bashrc)
source <(zrex completion bash)

# fish
zrex completion fish | source
```

## Controls While Attached

| Input | Action |
| --- | --- |
| `Ctrl-\` | Detach and leave the session running |

All other input—including keys, bracketed paste, Kitty keyboard sequences, and mouse events when requested by a running program—is passed directly to the remote block. Scrollback, search, and text selection are handled natively by your host terminal.

To switch to another window or split block, detach with `Ctrl-\` and attach again with `--window` or `--block`.

## Documentation

See [`docs/architecture.md`](docs/architecture.md) for codebase structure, Rex protocol details, and the stream rehydration architecture.
