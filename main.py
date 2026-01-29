#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import curses
import os
import sys

from app import App, AppConfig
from tui import run_tui


def default_cache_path() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "f2b_cache.sqlite3")


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="fail2ban/sshd monitor (ncurses TUI)")
    p.add_argument("--auth", default="/var/log/auth.log", help="path to auth.log")
    p.add_argument("--f2b", default="/var/log/fail2ban.log", help="path to fail2ban.log")
    p.add_argument("--sqlite", default="/var/lib/fail2ban/fail2ban.sqlite3", help="path to fail2ban sqlite")
    p.add_argument("--jail", default="", help="fail2ban jail to poll bans from (enables polling)")
    p.add_argument("--show-ok", action="store_true", help="show OK (Accepted ...) events/counters")
    p.add_argument("--poll-bans", dest="poll_bans", action="store_true", default=True, help="enable poll bans (default)")
    p.add_argument("--no-poll-bans", dest="poll_bans", action="store_false", help="disable poll bans")
    p.add_argument("--poll-interval", type=float, default=2.0, help="poll interval seconds")

    p.add_argument("--cache", default=default_cache_path(), help="cache sqlite path")
    p.add_argument("--subnet-prefix", type=int, default=24, choices=[8, 16, 24, 32], help="subnet prefix for subnet_cache")
    p.add_argument("--bootstrap-from-cache", type=int, default=100, help="seed realtime with N recent IPs from cache (0=off)")

    p.add_argument("--import-on-start", dest="import_on_start", action="store_true", default=True, help="import fail2ban history on start (default)")
    p.add_argument("--no-import-on-start", dest="import_on_start", action="store_false", help="disable import on start")

    p.add_argument("--asn-enable", dest="asn_enable", action="store_true", default=True, help="enable ASN whois (default)")
    p.add_argument("--no-asn-enable", dest="asn_enable", action="store_false", help="disable ASN whois")
    p.add_argument("--asn-refresh-interval", type=float, default=10.0, help="asn refresh interval seconds")
    p.add_argument("--asn-cache-ttl", type=int, default=24 * 3600, help="asn cache ttl seconds")
    p.add_argument("--asn-batch", type=int, default=20, help="asn batch size per refresh")
    p.add_argument("--asn-timeout", type=float, default=4.0, help="asn nc timeout seconds")

    p.add_argument("--cymru-host", default="whois.cymru.com", help="whois host (domain or IP), default whois.cymru.com")
    p.add_argument("--top-subnets", type=int, default=10, help="size of top subnets list")
    return p


def main(argv: list[str]) -> int:
    args = build_arg_parser().parse_args(argv)

    poll_bans = bool(args.poll_bans and args.jail)

    cfg = AppConfig(
        auth_log=str(args.auth),
        f2b_log=str(args.f2b),
        f2b_sqlite=str(args.sqlite),
        jail=str(args.jail),
        show_ok=bool(args.show_ok),
        poll_bans=poll_bans,
        poll_interval=float(args.poll_interval),
        cache_path=str(args.cache),
        subnet_prefix=int(args.subnet_prefix),
        bootstrap_from_cache=int(args.bootstrap_from_cache),
        import_on_start=bool(args.import_on_start),
        asn_enable=bool(args.asn_enable),
        asn_refresh_interval=float(args.asn_refresh_interval),
        asn_cache_ttl=int(args.asn_cache_ttl),
        asn_batch=int(args.asn_batch),
        asn_timeout=float(args.asn_timeout),
        cymru_host=str(args.cymru_host),
        top_subnets=int(args.top_subnets),
    )

    app = App(cfg)
    try:
        curses.wrapper(lambda stdscr: run_tui(stdscr, app))
    finally:
        app.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
