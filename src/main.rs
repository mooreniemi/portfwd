use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::Read,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver, TryRecvError},
    thread,
    time::{Duration, Instant},
};

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Default)]
struct Forward {
    name: String,
    host: String,
    local_port: u16,
    remote_host: String,
    remote_port: u16,
    /// Whether it should be turned on when the app starts.
    #[serde(default)]
    autostart: bool,
}

enum State {
    Off,
    Running(Child),
    Failed(String),
}

struct Entry {
    fwd: Forward,
    state: State,
}

impl Entry {
    fn start(&mut self) {
        self.stop();
        let spec = format!(
            "{}:{}:{}",
            self.fwd.local_port, self.fwd.remote_host, self.fwd.remote_port
        );
        let child = Command::new("ssh")
            .args(["-N", "-T", "-o", "ExitOnForwardFailure=yes"])
            .args(["-o", "BatchMode=yes", "-o", "ServerAliveInterval=30"])
            .args(["-o", "RequestTTY=no", "-o", "RemoteCommand=none"])
            .args(["-L", &spec, &self.fwd.host])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn();
        self.state = match child {
            Ok(c) => State::Running(c),
            Err(e) => State::Failed(e.to_string()),
        };
    }

    fn stop(&mut self) {
        if let State::Running(c) = &mut self.state {
            let _ = c.kill();
            let _ = c.wait();
        }
        self.state = State::Off;
    }

    /// Detect a dead ssh process and capture its error.
    fn poll(&mut self) {
        if let State::Running(c) = &mut self.state {
            if let Ok(Some(status)) = c.try_wait() {
                let mut err = String::new();
                if let Some(mut s) = c.stderr.take() {
                    let _ = s.read_to_string(&mut err);
                }
                let err = err.lines().last().unwrap_or("").trim().to_string();
                self.state = State::Failed(if err.is_empty() {
                    format!("ssh exited ({status})")
                } else {
                    err
                });
            }
        }
    }
}

const LABELS: [&str; 5] = ["Name", "SSH host", "Local port", "Remote host", "Remote port"];

#[derive(Clone)]
struct Listener {
    port: u16,
    bind: String,
    proc: String,
}

/// Ask `host` which TCP ports are listening (via ss, falling back to lsof).
fn fetch_listeners(host: &str) -> Result<Vec<Listener>, String> {
    let script = "if command -v ss >/dev/null 2>&1; then echo __ss; ss -tlnp 2>/dev/null; \
                  else echo __lsof; lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null; fi";
    let out = Command::new("ssh")
        .args(["-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5"])
        .args(["-o", "RequestTTY=no", "-o", "RemoteCommand=none", host, script])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = text.lines();
    let kind = lines.next().unwrap_or("");
    if kind != "__ss" && kind != "__lsof" {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(err.lines().last().unwrap_or("no output from host").trim().to_string());
    }
    let mut map: BTreeMap<u16, Listener> = BTreeMap::new();
    for l in lines {
        let f: Vec<&str> = l.split_whitespace().collect();
        let (addr, proc) = if kind == "__ss" {
            if f.len() < 5 || f[0] == "State" {
                continue;
            }
            (f[3], f.get(5).and_then(|p| p.split('"').nth(1)).unwrap_or(""))
        } else {
            if f.len() < 9 || f[0] == "COMMAND" {
                continue;
            }
            (f[8], f[0])
        };
        let Some((bind, port)) = addr.rsplit_once(':') else { continue };
        let Ok(port) = port.parse::<u16>() else { continue };
        let scope = if bind.starts_with("127.") || bind == "[::1]" { "loopback" } else { "all" };
        let e = map.entry(port).or_insert(Listener {
            port,
            bind: scope.into(),
            proc: String::new(),
        });
        if e.proc.is_empty() {
            e.proc = proc.to_string();
        }
    }
    Ok(map.into_values().collect())
}

/// First local port at or after `port` that we can bind (avoids clashes).
fn free_local_port(port: u16) -> u16 {
    let mut p = if port < 1024 { port + 8000 } else { port };
    while p < u16::MAX && TcpListener::bind(("127.0.0.1", p)).is_err() {
        p += 1;
    }
    p
}

struct Disc {
    host: String,
    hosts: Vec<String>,
    items: Vec<Listener>,
    error: Option<String>,
    rx: Option<Receiver<Result<Vec<Listener>, String>>>,
    last: Instant,
    table: TableState,
    filter: String,
    filtering: bool,
    /// (host, remote_port) pairs already configured; hidden from the discovered list.
    taken: Vec<(String, u16)>,
}

impl Disc {
    fn new(hosts: Vec<String>, host: String, taken: Vec<(String, u16)>) -> Self {
        let mut d = Disc {
            host,
            hosts,
            items: vec![],
            error: None,
            rx: None,
            last: Instant::now(),
            table: TableState::default(),
            filter: String::new(),
            filtering: false,
            taken,
        };
        d.kick();
        d
    }

    fn kick(&mut self) {
        let (tx, rx) = mpsc::channel();
        let host = self.host.clone();
        thread::spawn(move || {
            let _ = tx.send(fetch_listeners(&host));
        });
        self.rx = Some(rx);
        self.last = Instant::now();
    }

    /// Listeners matching the filter (process name or port, case-insensitive).
    fn visible(&self) -> Vec<&Listener> {
        let q = self.filter.to_lowercase();
        self.items
            .iter()
            .filter(|l| !self.taken.iter().any(|(h, p)| *h == self.host && *p == l.port))
            .filter(|l| {
                q.is_empty() || l.proc.to_lowercase().contains(&q) || l.port.to_string().contains(&q)
            })
            .collect()
    }

    fn selected(&self) -> Option<&Listener> {
        self.table.selected().and_then(|i| self.visible().get(i).copied())
    }

    fn reselect(&mut self, keep: Option<u16>) {
        let v = self.visible();
        let idx = keep
            .and_then(|p| v.iter().position(|l| l.port == p))
            .or(if v.is_empty() { None } else { Some(0) });
        self.table.select(idx);
    }

    /// Collect a finished poll, or start the next one every 5s.
    fn tick(&mut self) {
        let Some(rx) = &self.rx else {
            if self.last.elapsed() > Duration::from_secs(5) {
                self.kick();
            }
            return;
        };
        match rx.try_recv() {
            Ok(res) => {
                self.rx = None;
                self.last = Instant::now();
                match res {
                    Ok(items) => {
                        let keep = self.selected().map(|l| l.port);
                        self.items = items;
                        self.error = None;
                        self.reselect(keep);
                    }
                    Err(e) => self.error = Some(e),
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => self.rx = None,
        }
    }
}

/// Background check of which ports are listening on a host.
struct Probe {
    rx: Option<Receiver<Result<Vec<Listener>, String>>>,
    last: Instant,
    result: Option<Result<Vec<Listener>, String>>,
}

enum Mode {
    Normal,
    Discover(Disc),
    /// Full, untruncated details for one forward: (title, label/value pairs).
    View(String, Vec<(&'static str, String)>),
    /// (index being edited or None for new, field values, active field)
    Form(Option<usize>, [String; 5], usize),
    ConfirmDelete(usize),
}

struct App {
    entries: Vec<Entry>,
    probes: HashMap<String, Probe>,
    table: TableState,
    mode: Mode,
    msg: String,
    quit: bool,
}

fn config_path() -> PathBuf {
    let dir = dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("portfwd");
    let _ = fs::create_dir_all(&dir);
    dir.join("config.json")
}

impl App {
    fn load() -> Self {
        let fwds: Vec<Forward> = fs::read_to_string(config_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(|| {
                vec![Forward {
                    name: "jupyter".into(),
                    host: "rose".into(),
                    local_port: 8888,
                    remote_host: "localhost".into(),
                    remote_port: 8888,
                    autostart: false,
                }]
            });
        let mut entries: Vec<Entry> = fwds
            .into_iter()
            .map(|fwd| Entry { fwd, state: State::Off })
            .collect();
        for e in entries.iter_mut().filter(|e| e.fwd.autostart) {
            e.start();
        }
        let mut table = TableState::default();
        if !entries.is_empty() {
            table.select(Some(0));
        }
        App { entries, probes: HashMap::new(), table, mode: Mode::Normal, msg: String::new(), quit: false }
    }

    fn save(&mut self) {
        // "autostart" remembers what was on when you last changed anything.
        for e in &mut self.entries {
            e.fwd.autostart = matches!(e.state, State::Running(_));
        }
        let fwds: Vec<&Forward> = self.entries.iter().map(|e| &e.fwd).collect();
        if let Ok(s) = serde_json::to_string_pretty(&fwds) {
            let _ = fs::write(config_path(), s);
        }
    }

    /// Keep each host's listening-port list fresh (every 5s, off the UI thread).
    fn tick_probes(&mut self) {
        for e in &self.entries {
            self.probes.entry(e.fwd.host.clone()).or_insert(Probe {
                rx: None,
                last: Instant::now() - Duration::from_secs(60),
                result: None,
            });
        }
        for (host, p) in self.probes.iter_mut() {
            if let Some(rx) = &p.rx {
                match rx.try_recv() {
                    Ok(r) => {
                        p.result = Some(r);
                        p.rx = None;
                        p.last = Instant::now();
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => p.rx = None,
                }
            } else if p.last.elapsed() > Duration::from_secs(5) {
                let (tx, rx) = mpsc::channel();
                let h = host.clone();
                thread::spawn(move || {
                    let _ = tx.send(fetch_listeners(&h));
                });
                p.rx = Some(rx);
                p.last = Instant::now();
            }
        }
    }

    /// Some(true/false) if we know whether the remote port is listening;
    /// None if unknown (not probed yet, host unreachable, or non-local target).
    fn remote_up(&self, f: &Forward) -> Option<bool> {
        if !matches!(f.remote_host.as_str(), "localhost" | "127.0.0.1" | "::1") {
            return None;
        }
        match self.probes.get(&f.host)?.result.as_ref()? {
            Ok(v) => Some(v.iter().any(|l| l.port == f.remote_port)),
            Err(_) => None,
        }
    }

    fn selected(&self) -> Option<usize> {
        self.table.selected().filter(|&i| i < self.entries.len())
    }

    fn discover_key(&mut self, code: KeyCode) {
        let Mode::Discover(d) = &mut self.mode else { return };
        if d.filtering {
            match code {
                KeyCode::Esc => {
                    d.filter.clear();
                    d.filtering = false;
                    d.reselect(None);
                }
                KeyCode::Enter => d.filtering = false,
                KeyCode::Backspace => {
                    d.filter.pop();
                    d.reselect(None);
                }
                KeyCode::Char(c) => {
                    d.filter.push(c);
                    d.reselect(None);
                }
                KeyCode::Down | KeyCode::Up => {
                    let n = d.visible().len() as i32;
                    if n > 0 {
                        let step = if code == KeyCode::Down { 1 } else { -1 };
                        let cur = d.table.selected().unwrap_or(0) as i32;
                        d.table.select(Some((cur + step).rem_euclid(n) as usize));
                    }
                }
                _ => {}
            }
            return;
        }
        match code {
            KeyCode::Char('/') => d.filtering = true,
            KeyCode::Esc if !d.filter.is_empty() => {
                d.filter.clear();
                d.reselect(None);
            }
            KeyCode::Esc | KeyCode::Char('q') => self.mode = Mode::Normal,
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Up | KeyCode::Char('k') => {
                let n = d.visible().len() as i32;
                if n > 0 {
                    let step = if matches!(code, KeyCode::Down | KeyCode::Char('j')) { 1 } else { -1 };
                    let cur = d.table.selected().unwrap_or(0) as i32;
                    d.table.select(Some((cur + step).rem_euclid(n) as usize));
                }
            }
            KeyCode::Char('r') => d.kick(),
            KeyCode::Tab => {
                let i = d.hosts.iter().position(|h| *h == d.host).unwrap_or(0);
                d.host = d.hosts[(i + 1) % d.hosts.len()].clone();
                d.items.clear();
                d.error = None;
                d.table.select(None);
                d.kick();
            }
            KeyCode::Enter => {
                let Some(l) = d.selected().cloned() else { return };
                let host = d.host.clone();
                if self.entries.iter().any(|e| e.fwd.host == host && e.fwd.remote_port == l.port) {
                    self.msg = format!("{host}:{} is already in your list", l.port);
                    self.mode = Mode::Normal;
                    return;
                }
                let name = if l.proc.is_empty() { format!("port {}", l.port) } else { l.proc };
                self.msg.clear();
                self.mode = Mode::Form(
                    None,
                    [
                        name,
                        host,
                        free_local_port(l.port).to_string(),
                        "localhost".into(),
                        l.port.to_string(),
                    ],
                    0,
                );
            }
            _ => {}
        }
    }

    fn key(&mut self, code: KeyCode, mods: KeyModifiers) {
        if matches!(self.mode, Mode::Discover(_)) {
            return self.discover_key(code);
        }
        match &mut self.mode {
            Mode::Normal => match code {
                KeyCode::Char('q') => self.quit = true,
                KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => self.quit = true,
                KeyCode::Down | KeyCode::Char('j') => self.step(1),
                KeyCode::Up | KeyCode::Char('k') => self.step(-1),
                KeyCode::Enter | KeyCode::Char(' ') => {
                    if let Some(i) = self.selected() {
                        let running = matches!(self.entries[i].state, State::Running(_));
                        if running {
                            self.entries[i].stop();
                            self.msg.clear();
                        } else if self.remote_up(&self.entries[i].fwd) == Some(false) {
                            let f = &self.entries[i].fwd;
                            self.msg = format!(
                                "Nothing is listening on {}:{} — not starting",
                                f.host, f.remote_port
                            );
                            return;
                        } else {
                            self.msg.clear();
                            self.entries[i].start();
                        }
                        self.save();
                    }
                }
                KeyCode::Char('a') => {
                    self.mode = Mode::Form(
                        None,
                        [String::new(), "rose".into(), String::new(), "localhost".into(), String::new()],
                        0,
                    )
                }
                KeyCode::Char('e') => {
                    if let Some(i) = self.selected() {
                        let f = &self.entries[i].fwd;
                        self.mode = Mode::Form(
                            Some(i),
                            [
                                f.name.clone(),
                                f.host.clone(),
                                f.local_port.to_string(),
                                f.remote_host.clone(),
                                f.remote_port.to_string(),
                            ],
                            0,
                        );
                    }
                }
                KeyCode::Char('d') => {
                    if let Some(i) = self.selected() {
                        self.mode = Mode::ConfirmDelete(i);
                    }
                }
                KeyCode::Char('v') => {
                    if let Some(i) = self.selected() {
                        let e = &self.entries[i];
                        let f = &e.fwd;
                        let status = match &e.state {
                            State::Off => "off".to_string(),
                            State::Running(c) => format!("on (ssh pid {})", c.id()),
                            State::Failed(m) => format!("failed: {m}"),
                        };
                        let remote = match self.remote_up(f) {
                            Some(true) => "✓ listening".to_string(),
                            Some(false) => "⚠ not listening".to_string(),
                            None => "unknown".to_string(),
                        };
                        let fields = vec![
                            ("Name", f.name.clone()),
                            ("SSH host", f.host.clone()),
                            ("Local", format!("localhost:{}", f.local_port)),
                            ("Remote", format!("{}:{}", f.remote_host, f.remote_port)),
                            ("Status", status),
                            ("Remote port", remote),
                            (
                                "Command",
                                format!(
                                    "ssh -N -L {}:{}:{} {}",
                                    f.local_port, f.remote_host, f.remote_port, f.host
                                ),
                            ),
                        ];
                        self.mode = Mode::View(f.name.clone(), fields);
                    }
                }
                KeyCode::Char('s') => {
                    let mut hosts: Vec<String> = vec![];
                    for e in &self.entries {
                        if !hosts.contains(&e.fwd.host) {
                            hosts.push(e.fwd.host.clone());
                        }
                    }
                    if hosts.is_empty() {
                        hosts.push("rose".into());
                    }
                    let host = self
                        .selected()
                        .map(|i| self.entries[i].fwd.host.clone())
                        .unwrap_or_else(|| hosts[0].clone());
                    self.msg.clear();
                    self.mode = Mode::Discover(Disc::new(
                        hosts,
                        host,
                        self.entries
                            .iter()
                            .map(|e| (e.fwd.host.clone(), e.fwd.remote_port))
                            .collect(),
                    ));
                }
                _ => {}
            },
            Mode::Discover(_) => {}
            Mode::View(..) => {
                if matches!(code, KeyCode::Esc | KeyCode::Char('q' | 'v') | KeyCode::Enter) {
                    self.mode = Mode::Normal;
                }
            }
            Mode::ConfirmDelete(i) => {
                let i = *i;
                if matches!(code, KeyCode::Char('y')) {
                    self.entries[i].stop();
                    self.entries.remove(i);
                    let n = self.entries.len();
                    self.table.select(if n == 0 { None } else { Some(i.min(n - 1)) });
                    self.save();
                }
                self.mode = Mode::Normal;
            }
            Mode::Form(idx, fields, active) => match code {
                KeyCode::Esc => self.mode = Mode::Normal,
                KeyCode::Tab | KeyCode::Down => *active = (*active + 1) % 5,
                KeyCode::BackTab | KeyCode::Up => *active = (*active + 4) % 5,
                KeyCode::Backspace => {
                    fields[*active].pop();
                }
                KeyCode::Char(c) => fields[*active].push(c),
                KeyCode::Enter => {
                    let lp = fields[2].trim().parse::<u16>();
                    let rp = fields[4].trim().parse::<u16>();
                    let (Ok(local_port), Ok(remote_port)) = (lp, rp) else {
                        self.msg = "Ports must be numbers 0-65535".into();
                        return;
                    };
                    if fields[1].trim().is_empty() {
                        self.msg = "SSH host is required".into();
                        return;
                    }
                    let fwd = Forward {
                        name: fields[0].trim().to_string(),
                        host: fields[1].trim().to_string(),
                        local_port,
                        remote_host: if fields[3].trim().is_empty() {
                            "localhost".into()
                        } else {
                            fields[3].trim().to_string()
                        },
                        remote_port,
                        autostart: false,
                    };
                    match *idx {
                        Some(i) => {
                            // Restart if it was running so changes take effect.
                            let was_running = matches!(self.entries[i].state, State::Running(_));
                            self.entries[i].stop();
                            self.entries[i].fwd = fwd;
                            if was_running {
                                self.entries[i].start();
                            }
                        }
                        None => {
                            self.entries.push(Entry { fwd, state: State::Off });
                            self.table.select(Some(self.entries.len() - 1));
                        }
                    }
                    self.msg.clear();
                    self.mode = Mode::Normal;
                    self.save();
                }
                _ => {}
            },
        }
    }

    fn step(&mut self, d: i32) {
        let n = self.entries.len() as i32;
        if n == 0 {
            return;
        }
        let cur = self.table.selected().unwrap_or(0) as i32;
        self.table.select(Some((cur + d).rem_euclid(n) as usize));
    }

    fn draw(&mut self, f: &mut Frame) {
        let chunks = Layout::vertical([Constraint::Min(3), Constraint::Length(2)]).split(f.area());

        let rows: Vec<Row> = self
            .entries
            .iter()
            .map(|e| {
                let down = self.remote_up(&e.fwd) == Some(false);
                let warn = Style::default().fg(Color::Yellow);
                let (status, style) = match &e.state {
                    State::Off if down => ("○ off · ⚠ not listening".to_string(), warn),
                    State::Off => ("○ off".to_string(), Style::default().fg(Color::DarkGray)),
                    State::Running(_) if down => ("● on · ⚠ not listening".to_string(), warn),
                    State::Running(_) => ("● on".to_string(), Style::default().fg(Color::Green)),
                    State::Failed(m) => (format!("✗ {m}"), Style::default().fg(Color::Red)),
                };
                Row::new(vec![
                    Cell::from(Span::styled(status, style)),
                    Cell::from(e.fwd.name.clone()),
                    Cell::from(e.fwd.host.clone()),
                    Cell::from(format!(
                        "localhost:{}  →  {}:{}",
                        e.fwd.local_port, e.fwd.remote_host, e.fwd.remote_port
                    )),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Length(34),
                Constraint::Length(20),
                Constraint::Length(14),
                Constraint::Min(20),
            ],
        )
        .header(
            Row::new(["Status", "Name", "Host", "Forward"])
                .style(Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        )
        .row_highlight_style(Style::default().bg(Color::Blue).fg(Color::White))
        .block(Block::default().borders(Borders::ALL).title(" portfwd "));
        f.render_stateful_widget(table, chunks[0], &mut self.table);

        let help = "↑/↓ move · space/enter toggle · v view · s scan host · a add · e edit · d delete · q quit";
        f.render_widget(
            Paragraph::new(vec![
                Line::styled(help, Style::default().fg(Color::DarkGray)),
                Line::styled(self.msg.clone(), Style::default().fg(Color::Yellow)),
            ]),
            chunks[1],
        );

        match &mut self.mode {
            Mode::Form(idx, fields, active) => {
                let area = centered(f.area(), 60, 11);
                f.render_widget(Clear, area);
                let title = if idx.is_some() { " Edit forward " } else { " New forward " };
                let mut lines: Vec<Line> = LABELS
                    .iter()
                    .zip(fields.iter())
                    .enumerate()
                    .map(|(i, (l, v))| {
                        let st = if i == *active {
                            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                        } else {
                            Style::default()
                        };
                        let cursor = if i == *active { "▏" } else { "" };
                        Line::styled(format!("{l:>12}: {v}{cursor}"), st)
                    })
                    .collect();
                lines.push(Line::raw(""));
                lines.push(Line::styled(
                    "tab next · enter save · esc cancel",
                    Style::default().fg(Color::DarkGray),
                ));
                f.render_widget(
                    Paragraph::new(lines)
                        .block(Block::default().borders(Borders::ALL).title(title)),
                    area,
                );
            }
            Mode::ConfirmDelete(i) => {
                let area = centered(f.area(), 44, 3);
                f.render_widget(Clear, area);
                f.render_widget(
                    Paragraph::new(format!("Delete '{}'? (y/n)", self.entries[*i].fwd.name))
                        .block(Block::default().borders(Borders::ALL)),
                    area,
                );
            }
            Mode::Discover(d) => {
                let area = centered(f.area(), 80, 26);
                f.render_widget(Clear, area);
                let q = d.filter.to_lowercase();
                let configured: Vec<&Entry> = self
                    .entries
                    .iter()
                    .filter(|e| e.fwd.host == d.host)
                    .filter(|e| {
                        q.is_empty()
                            || e.fwd.name.to_lowercase().contains(&q)
                            || e.fwd.remote_port.to_string().contains(&q)
                    })
                    .collect();
                let conf_h = (configured.len().max(1) as u16 + 3).min(9);
                let parts = Layout::vertical([Constraint::Length(conf_h), Constraint::Min(5)]).split(area);
                let scanned = d.error.is_none() && (!d.items.is_empty() || d.rx.is_none());

                // Section 1: what you already have configured for this host.
                let warn = Style::default().fg(Color::Yellow);
                let mut rows: Vec<Row> = configured
                    .iter()
                    .map(|e| {
                        let (on, on_style) = if matches!(e.state, State::Running(_)) {
                            ("● on", Style::default().fg(Color::Green))
                        } else {
                            ("○ off", Style::default().fg(Color::DarkGray))
                        };
                        let local = matches!(e.fwd.remote_host.as_str(), "localhost" | "127.0.0.1" | "::1");
                        let (valid, v_style) = if !local {
                            ("? not checkable", Style::default().fg(Color::DarkGray))
                        } else if !scanned {
                            ("… scanning", Style::default().fg(Color::DarkGray))
                        } else if d.items.iter().any(|l| l.port == e.fwd.remote_port) {
                            ("✓ listening", Style::default().fg(Color::Green))
                        } else {
                            ("⚠ not listening", warn)
                        };
                        Row::new(vec![
                            Cell::from(Span::styled(on, on_style)),
                            Cell::from(e.fwd.name.clone()),
                            Cell::from(format!("localhost:{} → {}", e.fwd.local_port, e.fwd.remote_port)),
                            Cell::from(Span::styled(valid, v_style)),
                        ])
                    })
                    .collect();
                if rows.is_empty() {
                    rows.push(Row::new(vec![Cell::from(Span::styled(
                        "(none configured for this host)",
                        Style::default().fg(Color::DarkGray),
                    ))]));
                }
                let conf = Table::new(
                    rows,
                    [
                        Constraint::Length(7),
                        Constraint::Length(20),
                        Constraint::Length(24),
                        Constraint::Min(16),
                    ],
                )
                .header(
                    Row::new(["", "Name", "Forward", "Remote"])
                        .style(Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
                )
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Green))
                        .title(format!(" Configured on {} ", d.host)),
                );
                f.render_widget(conf, parts[0]);

                // Section 2: listening ports found by the scan that aren't configured yet.
                let status = match (&d.error, d.rx.is_some()) {
                    (Some(e), _) => format!(" ✗ {e} "),
                    (None, true) if d.items.is_empty() => " scanning… ".to_string(),
                    _ => format!(" {} new ", d.visible().len()),
                };
                let search = if d.filtering {
                    format!(" /{}▏", d.filter)
                } else if !d.filter.is_empty() {
                    format!(" /{}", d.filter)
                } else {
                    String::new()
                };
                let hint = if d.filtering {
                    " type to filter · enter keep · esc clear "
                } else {
                    " enter forward · / search · tab host · r refresh · esc close "
                };
                let rows: Vec<Row> = d
                    .visible()
                    .into_iter()
                    .map(|l| {
                        Row::new(vec![
                            Cell::from(l.port.to_string()),
                            Cell::from(l.bind.clone()),
                            Cell::from(l.proc.clone()),
                        ])
                    })
                    .collect();
                let found = Table::new(
                    rows,
                    [Constraint::Length(7), Constraint::Length(10), Constraint::Min(20)],
                )
                .header(
                    Row::new(["Port", "Bind", "Process"])
                        .style(Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
                )
                .row_highlight_style(Style::default().bg(Color::Blue).fg(Color::White))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Cyan))
                        .title(format!(" Discovered, not configured ·{status}·{search} "))
                        .title_bottom(hint),
                );
                f.render_stateful_widget(found, parts[1], &mut d.table);
            }
            Mode::View(title, fields) => {
                let area = centered(f.area(), 76, fields.len() as u16 + 10);
                f.render_widget(Clear, area);
                let mut lines: Vec<Line> = fields
                    .iter()
                    .map(|(l, v)| {
                        Line::from(vec![
                            Span::styled(format!("{l:>12}: "), Style::default().add_modifier(Modifier::BOLD)),
                            Span::raw(v.clone()),
                        ])
                    })
                    .collect();
                lines.push(Line::raw(""));
                lines.push(Line::styled("esc/v close", Style::default().fg(Color::DarkGray)));
                f.render_widget(
                    Paragraph::new(lines)
                        .wrap(Wrap { trim: false })
                        .block(Block::default().borders(Borders::ALL).title(format!(" {title} "))),
                    area,
                );
            }
            Mode::Normal => {}
        }
    }
}

fn centered(r: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(r.width);
    let h = h.min(r.height);
    Rect::new(r.x + (r.width - w) / 2, r.y + (r.height - h) / 2, w, h)
}

fn main() -> Result<()> {
    let mut app = App::load();
    enable_raw_mode()?;
    execute!(std::io::stdout(), EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;

    let res = (|| -> Result<()> {
        while !app.quit {
            for e in &mut app.entries {
                e.poll();
            }
            app.tick_probes();
            if let Mode::Discover(d) = &mut app.mode {
                d.tick();
            }
            term.draw(|f| app.draw(f))?;
            if event::poll(Duration::from_millis(250))? {
                if let Event::Key(k) = event::read()? {
                    if k.kind == KeyEventKind::Press {
                        app.key(k.code, k.modifiers);
                    }
                }
            }
        }
        Ok(())
    })();

    // Remember what was on, then tear down tunnels.
    app.save();
    for e in &mut app.entries {
        e.stop();
    }
    disable_raw_mode()?;
    execute!(std::io::stdout(), LeaveAlternateScreen)?;
    res
}
