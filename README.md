# portfwd

A small terminal UI for managing SSH port forwards. Save the forwards you use, turn them on and off with a keypress, and scan a host to see which ports are actually listening so you can decide what to forward.

It shells out to your system `ssh`, so everything in your `~/.ssh/config` (host aliases, keys, jump hosts) just works.

## Features

- **Saved forwards.** Name them once, toggle them any time.
- **On/off at a glance.** Each forward shows `● on`, `○ off`, or `✗ <ssh error>`.
- **Remembers state.** Forwards that were on when you quit come back on at next launch.
- **Remote port check.** Hosts are polled every 5s. If nothing is listening on the remote port, the forward won't start and shows `⚠ not listening` (an already-running forward gets the same warning if the remote service goes away).
- **Discovery.** Scan a host for listening TCP ports, search them by process name or port, and turn one into a forward with a few keystrokes.
- **Clean shutdown.** All tunnels are killed when you quit.

## Install

Requires a Rust toolchain (1.87+) and `ssh` on your PATH.

```sh
cargo build --release
cp target/release/portfwd ~/.local/bin/   # or anywhere on your PATH
```

## Usage

```sh
portfwd
```

### Main list

| Key | Action |
| --- | --- |
| `↑` `↓` / `j` `k` | Move selection |
| `space` / `enter` | Toggle the selected forward on/off |
| `s` | Scan the selected forward's host (see below) |
| `v` | View all details for the selected forward (untruncated status, full command) |
| `a` | Add a forward |
| `e` | Edit a forward (restarts it if running) |
| `d` | Delete a forward (asks for `y` to confirm) |
| `q` | Quit |

A forward is a name, an SSH host (any alias from `~/.ssh/config`), a local port, a remote host (default `localhost`), and a remote port. Turning one on runs the equivalent of:

```sh
ssh -N -L <local_port>:<remote_host>:<remote_port> <host>
```

### Scanning a host

Press `s` to open the scan popup. It connects to the host, lists listening TCP ports, and refreshes every 5 seconds. It has two sections:

- **Configured** (green): your saved forwards for that host, with whether the remote port is currently listening (`✓ listening` / `⚠ not listening`).
- **Discovered, not configured** (cyan): ports found by the scan that you haven't set up yet.

| Key | Action |
| --- | --- |
| `↑` `↓` / `j` `k` | Move through discovered ports |
| `enter` | Open the add form pre-filled for the selected port |
| `/` | Search by process name or port (`enter` keeps the filter, `esc` clears it) |
| `tab` | Switch to the next host in your list |
| `r` | Refresh now |
| `esc` / `q` | Close |

When you forward a discovered port, the local port defaults to the same number, or the next free one if it's taken locally.

## Config

Forwards are stored as JSON in your OS config directory, e.g. `~/Library/Application Support/portfwd/config.json` on macOS or `~/.config/portfwd/config.json` on Linux:

```json
[
  {
    "name": "jupyter",
    "host": "rose",
    "local_port": 8888,
    "remote_host": "localhost",
    "remote_port": 8888,
    "autostart": false
  }
]
```

`autostart` is updated automatically to reflect which forwards were on the last time you changed anything or quit. You can edit the file by hand while portfwd isn't running.

## How it works and limitations

- Discovery runs `ss -tlnp` on the remote host, falling back to `lsof -nP -iTCP -sTCP:LISTEN`. Hosts with neither (e.g. plain Windows) won't scan.
- Process names are only visible for processes your remote user owns. Other ports show up without a name, so search them by port number.
- All ssh connections use `BatchMode=yes`, so hosts that need an interactive password or passphrase prompt will fail rather than hang. Use keys or an ssh-agent.
- The remote port check only covers targets on the ssh host itself (`localhost`, `127.0.0.1`, `::1`). A forward to another machine such as `db.internal:5432` can't be checked.
- Only local forwards (`-L`) are supported. There's no reverse (`-R`) or SOCKS (`-D`) support yet.
- Each polled host opens a fresh ssh connection every 5 seconds. Add `ControlMaster auto` / `ControlPersist` to that host in `~/.ssh/config` if you want to reuse one connection.

## License

MIT, see [LICENSE](LICENSE).
