# f2b_tui

A lightweight **ncurses TUI** for monitoring **fail2ban** and **sshd** activity in real time, with a persistent **SQLite cache**, ASN enrichment, subnet aggregation, search, and drill‑down details.

Designed for **Ubuntu 22.04 / 24.04**, runs as **root**, and uses **only the Python standard library**.

---

## Features

- **Realtime view**  
  Live FAIL / OK / BAN / UNBAN counters per IP (only shows active events; no zero-noise).

- **SQLite cache view**  
  Historical per‑IP aggregates imported from `fail2ban.sqlite3` with last‑seen timestamps.

- **Subnets view**  
  Aggregation by subnet (configurable prefix), unique IP counts, score, last activity.

- **ASN view**  
  Provider enrichment via Team Cymru bulk whois (ASN, country, organization).

- **Details panel (Enter)**  
  Drill down into IP / subnet / ASN:
  - realtime counters
  - cached aggregates
  - fail2ban history
  - provider info
  - recent in‑memory events

- **Search (`/`)**, scrolling, paging, footer hints.
- **Persistent cache** next to the script.
- **No external pip dependencies**.

---

## Screens

- Tabs: `realtime | sqlite | subnets | asn`
- Events panel at the bottom (~1/3 height)
- Details overlay with scroll

---

## Requirements

- Python **3.10+**
- Packages already present on Ubuntu:
  - `fail2ban`
- Run as **root** (needed to read logs and fail2ban state)

---

## Install

Clone and run directly:

```bash
git clone https://github.com/yourname/f2b_tui.git
cd f2b_tui
python3 main.py
```

No virtualenv, no pip install.

---

## Usage

```bash
python3 main.py [options]
```

### Common options

```text
--auth-log /var/log/auth.log
--f2b-log /var/log/fail2ban.log
--f2b-sqlite /var/lib/fail2ban/fail2ban.sqlite3
--jail sshd

--bootstrap-from-cache 100
--no-import-on-start

--subnet-prefix 24
--top-subnets 10

--asn-enable
--asn-refresh-interval 20
--asn-cache-ttl 604800
--asn-batch 20
```

Example:

```bash
python3 main.py   --jail sshd   --asn-enable   --subnet-prefix 24
```

---

## Key bindings

- `1–4` – switch tabs
- `/` – search
- `↑ ↓ PgUp PgDn Home End` – navigation
- `Enter` – details
- `Esc` – clear search / close details
- `q` – quit

---

## Architecture

Unix‑style split into small modules:

```text
main.py            entry point, argparse, curses wrapper
app.py             core logic and state
tui.py             ncurses UI
cache_db.py        sqlite schema and queries
fail2ban_sqlite.py import fail2ban history
parsers.py         log parsing
tailer.py          safe tail implementation
asn.py             Team Cymru bulk whois
model.py           dataclasses
utils.py           helpers
```

All stateful data lives in SQLite; the TUI is a pure view/controller.

---

## Notes

- Realtime tab shows **only live events** (no historical noise).
- SQLite and subnet views show **historical aggregates**.
- ASN lookups are rate‑limited and cached.
- Works well on servers with heavy background brute‑force traffic.

---

## License

GPL v3
