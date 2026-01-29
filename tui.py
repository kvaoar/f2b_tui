#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# tui.py

from __future__ import annotations

import curses
import time
from typing import Callable, List, Optional, Sequence, Tuple

from model import DetailsState, ListState
from utils import clamp, now_utc_str, fmt_epoch_utc


TAB_ORDER = ["realtime", "sqlite", "subnets", "asn"]


def safe_addnstr(win, y: int, x: int, s: str, n: int, attr: int = 0) -> None:
    try:
        maxy, maxx = win.getmaxyx()
        if y < 0 or y >= maxy or x < 0 or x >= maxx:
            return
        if n <= 0:
            return
        # clip to available width
        avail = maxx - x
        if avail <= 0:
            return
        n2 = min(n, avail)
        win.addnstr(y, x, s, n2, attr)
    except Exception:
        return


def draw_tabs(stdscr, active: str, w: int) -> None:
    x = 0
    for t in TAB_ORDER:
        label = f" {t} "
        attr = curses.A_REVERSE if t == active else curses.A_BOLD
        safe_addnstr(stdscr, 0, x, label, len(label), attr)
        x += len(label)
    # right side time
    ts = now_utc_str()
    if w - len(ts) - 1 > x:
        safe_addnstr(stdscr, 0, w - len(ts) - 1, ts, len(ts), curses.A_DIM)


def draw_footer(stdscr, h: int, w: int, ls: ListState, hint: str) -> None:
    y = h - 1
    s = f"tab={ls.tab}  cursor={ls.cursor}  offset={ls.offset}  search=/{ls.search}   {hint}"
    safe_addnstr(stdscr, y, 0, " " * (w - 1), w - 1, curses.A_REVERSE)
    safe_addnstr(stdscr, y, 0, s, w - 1, curses.A_REVERSE)


def _calc_layout(h: int) -> Tuple[int, int, int]:
    """
    Returns (list_h, events_h, footer_h)
    We keep: tabs line at 0, footer at last line.
    Events panel ~ 1/3 height.
    """
    footer_h = 1
    tabs_h = 1
    usable = max(1, h - tabs_h - footer_h)
    events_h = max(3, usable // 3)
    list_h = max(1, usable - events_h)
    return (list_h, events_h, footer_h)


def prompt_search(stdscr, h: int, w: int, current: str) -> str:
    curses.curs_set(1)
    buf = current
    y = h - 1
    while True:
        s = f"/{buf}"
        safe_addnstr(stdscr, y, 0, " " * (w - 1), w - 1, curses.A_REVERSE)
        safe_addnstr(stdscr, y, 0, s, w - 1, curses.A_REVERSE)
        stdscr.refresh()
        ch = stdscr.getch()
        if ch in (27,):  # ESC
            curses.curs_set(0)
            return current
        if ch in (10, 13):  # Enter
            curses.curs_set(0)
            return buf
        if ch in (curses.KEY_BACKSPACE, 127, 8):
            buf = buf[:-1]
            continue
        if 0 <= ch <= 255:
            c = chr(ch)
            if c.isprintable():
                buf += c


def _read_key(stdscr) -> int:
    ch = stdscr.getch()
    if ch != 27:
        return ch
    nxt = stdscr.getch()
    if nxt == -1:
        return ch
    if nxt != 91:  # '['
        return ch
    third = stdscr.getch()
    if third == -1:
        return ch
    if third == 65:
        return curses.KEY_UP
    if third == 66:
        return curses.KEY_DOWN
    if third == 67:
        return curses.KEY_RIGHT
    if third == 68:
        return curses.KEY_LEFT
    if third == 72:
        return curses.KEY_HOME
    if third == 70:
        return curses.KEY_END
    if third in (49, 52, 53, 54):
        fourth = stdscr.getch()
        if fourth == 126:
            if third == 49:
                return curses.KEY_HOME
            if third == 52:
                return curses.KEY_END
            if third == 53:
                return curses.KEY_PPAGE
            if third == 54:
                return curses.KEY_NPAGE
    return ch


def _details_page_size(h: int) -> int:
    inner_h = max(1, (max(5, h - 4) - 2))
    return max(1, inner_h)


def draw_list_panel(stdscr, y0: int, h: int, w: int, title: str, rows: List[str], ls: ListState) -> None:
    safe_addnstr(stdscr, y0, 0, " " * (w - 1), w - 1, curses.A_BOLD)
    safe_addnstr(stdscr, y0, 0, f" {title}", w - 1, curses.A_BOLD)
    # content starts next line
    y = y0 + 1
    max_rows = max(0, h - 1)
    total = len(rows)
    ls.cursor = clamp(ls.cursor, 0, max(0, total - 1))
    # ensure cursor visible
    if ls.cursor < ls.offset:
        ls.offset = ls.cursor
    if ls.cursor >= ls.offset + max_rows:
        ls.offset = max(0, ls.cursor - max_rows + 1)
    ls.offset = clamp(ls.offset, 0, max(0, total - max_rows))

    for i in range(max_rows):
        idx = ls.offset + i
        line = rows[idx] if idx < total else ""
        attr = curses.A_REVERSE if idx == ls.cursor else 0
        safe_addnstr(stdscr, y + i, 0, " " * (w - 1), w - 1, attr)
        safe_addnstr(stdscr, y + i, 0, line, w - 1, attr)


def draw_events_panel(stdscr, y0: int, h: int, w: int, lines: List[str]) -> None:
    safe_addnstr(stdscr, y0, 0, " " * (w - 1), w - 1, curses.A_DIM)
    safe_addnstr(stdscr, y0, 0, " events", w - 1, curses.A_DIM)
    max_rows = max(0, h - 1)
    # show last max_rows lines
    tail = lines[-max_rows:]
    for i in range(max_rows):
        line = tail[i] if i < len(tail) else ""
        safe_addnstr(stdscr, y0 + 1 + i, 0, " " * (w - 1), w - 1, 0)
        safe_addnstr(stdscr, y0 + 1 + i, 0, line, w - 1, 0)


def draw_details_overlay(stdscr, ds: DetailsState) -> None:
    h, w = stdscr.getmaxyx()
    # centered box with margin
    mh = 2
    mw = 4
    y0 = mh
    x0 = mw
    hh = max(5, h - 2 * mh)
    ww = max(10, w - 2 * mw)
    # border
    for x in range(x0, x0 + ww):
        safe_addnstr(stdscr, y0, x, " ", 1, curses.A_REVERSE)
        safe_addnstr(stdscr, y0 + hh - 1, x, " ", 1, curses.A_REVERSE)
    for y in range(y0, y0 + hh):
        safe_addnstr(stdscr, y, x0, " ", 1, curses.A_REVERSE)
        safe_addnstr(stdscr, y, x0 + ww - 1, " ", 1, curses.A_REVERSE)
    # title
    safe_addnstr(stdscr, y0, x0 + 2, f" {ds.title} ", ww - 4, curses.A_REVERSE)
    inner_y0 = y0 + 1
    inner_h = hh - 2
    inner_w = ww - 2
    total = len(ds.lines)
    ds.cursor = clamp(ds.cursor, 0, max(0, total - 1))
    if ds.cursor < ds.offset:
        ds.offset = ds.cursor
    if ds.cursor >= ds.offset + inner_h:
        ds.offset = max(0, ds.cursor - inner_h + 1)
    ds.offset = clamp(ds.offset, 0, max(0, total - inner_h))
    for i in range(inner_h):
        idx = ds.offset + i
        line = ds.lines[idx] if idx < total else ""
        safe_addnstr(stdscr, inner_y0 + i, x0 + 1, " " * inner_w, inner_w, 0)
        safe_addnstr(stdscr, inner_y0 + i, x0 + 1, line, inner_w, 0)
    # footer hint inside
    hint = "ESC/q close  Up/Down/PgUp/PgDn/Home/End scroll"
    safe_addnstr(stdscr, y0 + hh - 1, x0 + 2, hint, ww - 4, curses.A_REVERSE)


def run_tui(stdscr, app) -> None:
    curses.curs_set(0)
    curses.use_default_colors()
    stdscr.nodelay(True)
    stdscr.keypad(True)

    ls_by_tab = {t: ListState(tab=t) for t in TAB_ORDER}
    ds = DetailsState(open=False)

    active = "realtime"
    last_render = 0.0

    while True:
        h, w = stdscr.getmaxyx()
        list_h, events_h, _ = _calc_layout(h)

        # query data for active tab
        ls = ls_by_tab[active]
        if active == "realtime":
            rows_data = app.get_realtime_rows(ls.search)
            rows = []
            for ip, st in rows_data:
                rows.append(f"{ip:15}  FAIL={st.get('FAIL',0):5} OK={st.get('OK',0):5} BAN={st.get('BAN',0):5} UNBAN={st.get('UNBAN',0):5}")
        elif active == "sqlite":
            rows_data = app.get_sqlite_rows(ls.search, limit=None)
            rows = []
            for r in rows_data:
                rows.append(
                    f"{r['ip']:15}  ban_total={r['ban_count_total']:7} bans={r['bans']:6} fails={r['fails']:6} "
                    f"last_seen={fmt_epoch_utc(r['last_seen_ts'])}"
                )
        elif active == "subnets":
            rows_data = app.get_subnet_rows(ls.search)
            rows = []
            for r in rows_data:
                score = int(r["bans"] or 0) + int(r["fails"] or 0)
                rows.append(f"{r['subnet']:18}  score={score:8} unique_ips={r['unique_ips']:6} bans={r['bans']:6} fails={r['fails']:6} last_seen={fmt_epoch_utc(r['last_seen_ts'])}")
        else:  # asn
            rows_data = app.get_asn_rows(ls.search)
            rows = []
            for r in rows_data:
                rows.append(f"AS{r['asn']:>6}  {r['cc']:<2}  ip_count={r['ip_count']:6} ban_sum={r['ban_total_sum']:8} bans={r['bans_sum']:8} fails={r['fails_sum']:8}  {r['as_name']}")
        events_lines = app.get_events_lines(max_lines=300)

        # periodic tasks (asn/poll/commit)
        app.process_log_tails()
        app.periodic()

        # render
        now = time.time()
        if now - last_render >= 0.05:
            stdscr.erase()
            draw_tabs(stdscr, active, w)
            y_list = 1
            draw_list_panel(stdscr, y_list, list_h, w, f"{active} ({len(rows)})", rows, ls)
            y_events = 1 + list_h
            draw_events_panel(stdscr, y_events, events_h, w, events_lines)
            draw_footer(stdscr, h, w, ls, "Tab:1-4  / search  Enter details  ESC clear  q quit")
            if ds.open:
                draw_details_overlay(stdscr, ds)
            stdscr.refresh()
            last_render = now

        # input
        ch = _read_key(stdscr)
        if ch == -1:
            time.sleep(0.01)
            continue
        if ds.open:
            # details keys
            if ch in (27, ord('q')):
                ds.open = False
                continue
            if ch == curses.KEY_UP:
                ds.cursor -= 1
            elif ch == curses.KEY_DOWN:
                ds.cursor += 1
            elif ch == curses.KEY_PPAGE:
                ds.cursor -= _details_page_size(h)
            elif ch == curses.KEY_NPAGE:
                ds.cursor += _details_page_size(h)
            elif ch == curses.KEY_HOME:
                ds.cursor = 0
            elif ch == curses.KEY_END:
                ds.cursor = max(0, len(ds.lines) - 1)
            continue

        if ch in (ord('q'),):
            break
        if ch in (27,):  # ESC clears search
            ls.search = ""
            ls.cursor = 0
            ls.offset = 0
            continue
        if ch in (ord('1'),):
            active = "realtime"
            continue
        if ch in (ord('2'),):
            active = "sqlite"
            continue
        if ch in (ord('3'),):
            active = "subnets"
            continue
        if ch in (ord('4'),):
            active = "asn"
            continue
        if ch in (ord('/'),):
            ls.search = prompt_search(stdscr, h, w, ls.search)
            ls.cursor = 0
            ls.offset = 0
            continue

        if ch == curses.KEY_UP:
            ls.cursor -= 1
        elif ch == curses.KEY_DOWN:
            ls.cursor += 1
        elif ch == curses.KEY_PPAGE:
            ls.cursor -= max(1, list_h - 2)
        elif ch == curses.KEY_NPAGE:
            ls.cursor += max(1, list_h - 2)
        elif ch == curses.KEY_HOME:
            ls.cursor = 0
        elif ch == curses.KEY_END:
            ls.cursor = max(0, len(rows) - 1)
        elif ch in (10, 13):  # Enter -> details
            if not rows:
                continue
            idx = clamp(ls.cursor, 0, len(rows) - 1)
            if active in ("realtime", "sqlite"):
                # parse IP at start of line
                ip = rows[idx].split()[0]
                ds.title = f"details ip {ip}"
                ds.lines = app.get_ip_details(ip)
                ds.cursor = 0
                ds.offset = 0
                ds.open = True
            elif active == "subnets":
                subnet = rows[idx].split()[0]
                ds.title = f"details subnet {subnet}"
                ds.lines = app.get_subnet_details(subnet)
                ds.cursor = 0
                ds.offset = 0
                ds.open = True
            else:
                # AS line starts with ASxxxxx
                tok = rows[idx].split()[0]
                asn = tok[2:] if tok.startswith("AS") else tok
                ds.title = f"details ASN {asn}"
                ds.lines = app.get_asn_details(asn)
                ds.cursor = 0
                ds.offset = 0
                ds.open = True
