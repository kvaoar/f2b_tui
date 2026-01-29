#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# app.py

from __future__ import annotations

import os
import re
import subprocess
import time
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional, Set, Tuple

from asn import cymru_bulk_lookup_nc
from cache_db import CacheDB
from fail2ban_sqlite import fetch_ip_history_bips, import_bips_aggregates, source_fingerprint
from model import ASNInfo, Event
from parsers import parse_f2b_line, parse_ssh_line
from tailer import TailFile
from utils import fmt_epoch_utc, now_ts, now_utc_str


@dataclass
class AppConfig:
    auth_log: str
    f2b_log: str
    f2b_sqlite: str
    jail: str
    show_ok: bool
    poll_bans: bool
    poll_interval: float
    cache_path: str
    subnet_prefix: int
    bootstrap_from_cache: int
    import_on_start: bool
    asn_enable: bool
    asn_refresh_interval: float
    asn_cache_ttl: int
    asn_batch: int
    asn_timeout: float
    cymru_host: str
    top_subnets: int


class App:
    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.cache = CacheDB(cfg.cache_path)
        self.events: Deque[Event] = deque(maxlen=2000)
        self.ip_events: Dict[str, Deque[Event]] = {}
        self.realtime: Dict[str, Dict[str, int]] = {}
        self._pending_sql_ops: int = 0
        self._last_commit_ts: float = time.time()
        self._commit_interval: float = 0.8

        self.t_auth = TailFile(cfg.auth_log, start_at_end=True)
        self.t_f2b = TailFile(cfg.f2b_log, start_at_end=True)

        self._last_poll_ts: float = 0.0
        self._poll_known: Set[str] = set()

        self._last_asn_ts: float = 0.0
        self._asn_cursor: Optional[str] = None

        if cfg.import_on_start:
            self.import_fail2ban_history()

        if cfg.bootstrap_from_cache > 0:
            self.bootstrap_realtime_from_cache(cfg.bootstrap_from_cache)

        # initial subnet unique count refresh (cheap for moderate sizes)
        try:
            self.cache.refresh_subnet_unique_counts()
            self.cache.con.commit()
        except Exception as e:
            self.log_sys("ERR", "", f"sqlite refresh_subnet_unique_counts failed: {e}")

    def close(self) -> None:
        try:
            self.cache.close()
        except Exception:
            pass

    def log_sys(self, kind: str, ip: str, msg: str) -> None:
        ev = Event(ts=now_ts(), src="sys", kind=kind, ip=ip, msg=msg)
        self.events.append(ev)

    def _push_event(self, ev: Event) -> None:
        self.events.append(ev)
        dq = self.ip_events.get(ev.ip)
        if dq is None:
            dq = deque(maxlen=50)
            self.ip_events[ev.ip] = dq
        dq.append(ev)

    def bootstrap_realtime_from_cache(self, n: int) -> None:
        try:
            ips = self.cache.list_realtime_seed_ips(n)
            for ip in ips:
                self.realtime.setdefault(ip, {"FAIL": 0, "OK": 0, "BAN": 0, "UNBAN": 0})
            self.log_sys("INFO", "", f"bootstrap realtime from cache: {len(ips)} IPs")
        except Exception as e:
            self.log_sys("ERR", "", f"bootstrap_from_cache failed: {e}")

    def import_fail2ban_history(self) -> None:
        src = self.cfg.f2b_sqlite
        try:
            st_mtime, st_size = source_fingerprint(src)
        except Exception as e:
            self.log_sys("ERR", "", f"fail2ban sqlite stat failed: {e}")
            return

        prev_mtime = self.cache.get_state("source_mtime")
        prev_size = self.cache.get_state("source_size")
        if prev_mtime == str(st_mtime) and prev_size == str(st_size):
            # already imported
            return

        try:
            agg = import_bips_aggregates(src)
        except Exception as e:
            self.log_sys("ERR", "", f"import bips aggregates failed: {e}")
            return

        imported = 0
        try:
            for ip, d in agg.items():
                self.cache.upsert_imported_bips(
                    ip=ip,
                    ban_count_total=int(d.get("ban_count_total", 0) or 0),
                    last_ban_ts=d.get("last_ban_ts", None),
                    last_ban_jail=str(d.get("last_ban_jail", "") or ""),
                    subnet_prefix=self.cfg.subnet_prefix,
                )
                imported += 1
                # batch commit by chunks
                if imported % 2000 == 0:
                    self.cache.con.commit()
            self.cache.refresh_subnet_unique_counts()
            self.cache.set_state("imported_at_ts", str(now_ts()))
            self.cache.set_state("source_sqlite_path", src)
            self.cache.set_state("source_mtime", str(st_mtime))
            self.cache.set_state("source_size", str(st_size))
            self.cache.set_state("last_import_rows", str(imported))
            self.cache.con.commit()
            self.log_sys("INFO", "", f"imported fail2ban history: {imported} IPs")
        except Exception as e:
            try:
                self.cache.con.rollback()
            except Exception:
                pass
            self.log_sys("ERR", "", f"import failed (rolled back): {e}")

    def _mark_sql_dirty(self) -> None:
        self._pending_sql_ops += 1

    def _maybe_commit(self) -> None:
        now = time.time()
        if self._pending_sql_ops <= 0:
            return
        if now - self._last_commit_ts >= self._commit_interval:
            try:
                self.cache.con.commit()
                self._pending_sql_ops = 0
                self._last_commit_ts = now
            except Exception as e:
                self.log_sys("ERR", "", f"sqlite commit failed: {e}")
                try:
                    self.cache.con.rollback()
                except Exception:
                    pass
                self._pending_sql_ops = 0
                self._last_commit_ts = now

    def process_log_tails(self) -> None:
        # auth.log
        for line in self.t_auth.read_available_lines():
            res = parse_ssh_line(line)
            if not res:
                continue
            ip, kind = res
            if kind == "OK" and not self.cfg.show_ok:
                continue
            self._handle_event(src="auth", kind=kind, ip=ip, jail="")
        # fail2ban.log
        for line in self.t_f2b.read_available_lines():
            res = parse_f2b_line(line)
            if not res:
                continue
            ip, kind, jail = res
            self._handle_event(src="f2b", kind=kind, ip=ip, jail=jail)

    def _handle_event(self, src: str, kind: str, ip: str, jail: str) -> None:
        ts = now_ts()
        # realtime counters
        rt = self.realtime.setdefault(ip, {"FAIL": 0, "OK": 0, "BAN": 0, "UNBAN": 0})
        if kind in rt:
            rt[kind] += 1
        # cache updates (batched commit elsewhere)
        try:
            self.cache.upsert_ip_event(ip, ts, kind, jail, self.cfg.show_ok, self.cfg.subnet_prefix)
            self._mark_sql_dirty()
        except Exception as e:
            self.log_sys("ERR", ip, f"sqlite upsert failed: {e}")

        ev = Event(ts=ts, src=src, kind=kind, ip=ip, jail=jail)
        self._push_event(ev)

    def poll_fail2ban_bans(self) -> None:
        if not self.cfg.poll_bans or not self.cfg.jail:
            return
        now = time.time()
        if now - self._last_poll_ts < self.cfg.poll_interval:
            return
        self._last_poll_ts = now

        # fail2ban-client status <jail> output differs by version; parse IP list from lines containing "Banned IP list:"
        cmd = ["fail2ban-client", "status", self.cfg.jail]
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3.0, check=False, text=True)
        except Exception as e:
            self.log_sys("ERR", "", f"poll fail2ban-client failed: {e}")
            return

        if proc.returncode != 0:
            return

        banned: Set[str] = set()
        for line in proc.stdout.splitlines():
            if "Banned IP list:" in line:
                # after colon, list of IPs separated by space
                parts = line.split("Banned IP list:", 1)[1].strip().split()
                for ip in parts:
                    if ip:
                        banned.add(ip)
        # diff
        added = banned - self._poll_known
        removed = self._poll_known - banned
        if not added and not removed:
            return
        for ip in sorted(added):
            self._handle_event(src="poll", kind="BAN", ip=ip, jail=self.cfg.jail)
        for ip in sorted(removed):
            self._handle_event(src="poll", kind="UNBAN", ip=ip, jail=self.cfg.jail)
        self._poll_known = banned

    def refresh_asn(self) -> Tuple[int, int]:
        if not self.cfg.asn_enable:
            return (0, 0)
        now = time.time()
        if now - self._last_asn_ts < self.cfg.asn_refresh_interval:
            return (0, 0)
        self._last_asn_ts = now

        ttl = int(self.cfg.asn_cache_ttl)
        cur_ts = now_ts()
        min_fetched_ts = cur_ts - ttl
        try:
            need = self.cache.list_ips_needing_asn_refresh(self._asn_cursor, int(self.cfg.asn_batch), min_fetched_ts)
            if not need and self._asn_cursor is not None:
                self._asn_cursor = None
                need = self.cache.list_ips_needing_asn_refresh(self._asn_cursor, int(self.cfg.asn_batch), min_fetched_ts)
        except Exception as e:
            self.log_sys("ERR", "", f"asn cache scan failed: {e}")
            return (0, 0)

        if not need:
            return (0, 0)

        self._asn_cursor = need[-1]
        try:
            res = cymru_bulk_lookup_nc(need, host=self.cfg.cymru_host, timeout_s=self.cfg.asn_timeout)
        except Exception as e:
            self.log_sys("ERR", "", f"asn lookup failed: {e}")
            return (len(need), 0)

        if not res:
            return (len(need), 0)

        try:
            asked, written = self.cache.upsert_asn_info(res)
            self._mark_sql_dirty()
            return (asked, written)
        except Exception as e:
            self.log_sys("ERR", "", f"asn sqlite write failed: {e}")
            return (len(need), 0)

    def periodic(self) -> None:
        self.poll_fail2ban_bans()
        asked, written = self.refresh_asn()
        if asked > 0 and written > 0:
            self.log_sys("INFO", "", f"asn refresh: asked={asked} got={written}")
        self._maybe_commit()

    # ---- Query APIs for TUI (no SQL details in TUI) ----

    def get_realtime_rows(self, search: str) -> List[Tuple[str, Dict[str, int]]]:
        items = list(self.realtime.items())

        # hide rows with all-zero counters (realtime tab = live events only)
        items = [
            (ip, st) for ip, st in items
            if (st.get("FAIL", 0) + st.get("OK", 0) + st.get("BAN", 0) + st.get("UNBAN", 0)) > 0
        ]

        if search:
            s = search.lower()
            items = [(ip, st) for ip, st in items if s in ip.lower()]
        # sort by BAN then FAIL then last activity heuristic (sum)
        items.sort(key=lambda t: (t[1].get("BAN", 0), t[1].get("FAIL", 0), sum(t[1].values())), reverse=True)
        return items

    def get_sqlite_rows(self, search: str, limit: Optional[int] = None) -> List[object]:
        try:
            return self.cache.list_ip_cache(search=search, limit=limit)
        except Exception as e:
            self.log_sys("ERR", "", f"list_ip_cache failed: {e}")
            return []

    def get_subnet_rows(self, search: str) -> List[object]:
        try:
            return self.cache.list_top_subnets(top_n=self.cfg.top_subnets, search=search)
        except Exception as e:
            self.log_sys("ERR", "", f"list_top_subnets failed: {e}")
            return []

    def get_asn_rows(self, search: str) -> List[object]:
        try:
            return self.cache.list_asn_summary(search=search, limit=200)
        except Exception as e:
            self.log_sys("ERR", "", f"list_asn_summary failed: {e}")
            return []

    def get_ip_details(self, ip: str) -> List[str]:
        lines: List[str] = []
        lines.append(f"IP: {ip}")
        lines.append("")
        # realtime
        rt = self.realtime.get(ip)
        if rt:
            lines.append("Realtime counters:")
            lines.append(f"  FAIL={rt.get('FAIL', 0)} OK={rt.get('OK', 0)} BAN={rt.get('BAN', 0)} UNBAN={rt.get('UNBAN', 0)}")
            lines.append("")
        # cache
        row = None
        try:
            row = self.cache.get_ip_row(ip)
        except Exception as e:
            lines.append(f"Cache read error: {e}")
        if row:
            lines.append("Cache ip_cache:")
            lines.append(f"  first_seen: {fmt_epoch_utc(row['first_seen_ts'])}")
            lines.append(f"  last_seen : {fmt_epoch_utc(row['last_seen_ts'])}")
            lines.append(f"  fails={row['fails']} oks={row['oks']} bans={row['bans']} unbans={row['unbans']}")
            lines.append(f"  last_event={row['last_event']} last_jail={row['last_jail']}")
            lines.append("")
            lines.append("Fail2ban history import (aggregates):")
            lines.append(f"  ban_count_total={row['ban_count_total']}")
            lines.append(f"  last_ban_ts  ={fmt_epoch_utc(row['last_ban_ts'])}")
            lines.append(f"  last_ban_jail={row['last_ban_jail']}")
            lines.append("")
            lines.append("Provider (cached):")
            lines.append(f"  ASN={row['provider_asn']} CC={row['provider_cc']}")
            lines.append(f"  Name={row['provider_name']}")
            lines.append(f"  Updated={fmt_epoch_utc(row['provider_fetched_ts'])}")
            lines.append("")
        else:
            lines.append("Cache ip_cache: (no row)")
            lines.append("")

        # belongs to top10 subnets?
        try:
            subrows = self.cache.list_top_subnets(top_n=self.cfg.top_subnets, search="")
            top_set = set(str(r["subnet"]) for r in subrows)
            subnet = ""
            try:
                subnet = ""
                # pick subnet of current prefix
                subnet = __import__("utils").ip_to_subnet(ip, self.cfg.subnet_prefix)
            except Exception:
                subnet = ""
            if subnet and subnet in top_set:
                lines.append(f"belongs_to_top10_subnets: yes ({subnet})")
            else:
                lines.append("belongs_to_top10_subnets: no")
        except Exception:
            lines.append("belongs_to_top10_subnets: -")
        lines.append("")

        # last K bips entries
        lines.append("Fail2ban history:")
        try:
            hist = fetch_ip_history_bips(self.cfg.f2b_sqlite, ip, limit=None)
            if not hist:
                lines.append("  (no rows)")
            else:
                for r in hist:
                    lines.append(f"  {fmt_epoch_utc(r['timeofban'])} jail={r['jail']} bantime={r['bantime']} bancount={r['bancount']}")
        except Exception as e:
            lines.append(f"  error: {e}")
        lines.append("")

        # in-memory events
        lines.append("Recent events (in-memory, up to 50):")
        dq = self.ip_events.get(ip)
        if not dq:
            lines.append("  (none)")
        else:
            for ev in list(dq)[-50:]:
                lines.append(f"  {fmt_epoch_utc(ev.ts)} {ev.src} {ev.kind} jail={ev.jail}")
        return lines

    def get_subnet_details(self, subnet: str) -> List[str]:
        lines: List[str] = []
        lines.append(f"Subnet: {subnet}")
        lines.append("")
        try:
            row = self.cache.get_subnet_row(subnet)
            if row:
                lines.append("Subnet cache:")
                lines.append(f"  prefix={row['prefix']}")
                lines.append(f"  first_seen={fmt_epoch_utc(row['first_seen_ts'])}")
                lines.append(f"  last_seen ={fmt_epoch_utc(row['last_seen_ts'])}")
                lines.append(f"  fails={row['fails']} bans={row['bans']} unbans={row['unbans']} unique_ips={row['unique_ips']}")
                lines.append(f"  last_ip={row['last_ip']}")
            else:
                lines.append("Subnet cache: (no row)")
        except Exception as e:
            lines.append(f"Subnet cache read error: {e}")
        lines.append("")

        # belongs to top10
        try:
            subrows = self.cache.list_top_subnets(top_n=self.cfg.top_subnets, search="")
            top = [str(r["subnet"]) for r in subrows]
            if subnet in top:
                lines.append(f"belongs_to_top10_subnets: yes (rank {top.index(subnet)+1}/{len(top)})")
            else:
                lines.append("belongs_to_top10_subnets: no")
        except Exception:
            lines.append("belongs_to_top10_subnets: -")
        lines.append("")

        lines.append("Top IPs in subnet:")
        try:
            ips = self.cache.list_ips_in_subnet(subnet, limit=50)
            if not ips:
                lines.append("  (no rows)")
            else:
                for r in ips:
                    lines.append(f"  {r['ip']} ban_total={r['ban_count_total']} bans={r['bans']} fails={r['fails']} last_seen={fmt_epoch_utc(r['last_seen_ts'])}")
        except Exception as e:
            lines.append(f"  error: {e}")
        return lines

    def get_asn_details(self, asn: str) -> List[str]:
        lines: List[str] = []
        lines.append(f"ASN: {asn}")
        lines.append("")
        # summary row
        try:
            rows = self.cache.list_asn_summary(search=asn, limit=10)
            row = None
            for r in rows:
                if str(r["asn"]) == asn:
                    row = r
                    break
            if row:
                lines.append("ASN summary:")
                lines.append(f"  CC={row['cc']}")
                lines.append(f"  Name={row['as_name']}")
                lines.append(f"  ip_count={row['ip_count']}")
                lines.append(f"  ban_total_sum={row['ban_total_sum']} bans_sum={row['bans_sum']} fails_sum={row['fails_sum']}")
                lines.append(f"  last_fetch={fmt_epoch_utc(row['last_fetch_ts'])}")
            else:
                lines.append("ASN summary: (no row)")
        except Exception as e:
            lines.append(f"ASN summary error: {e}")
        lines.append("")

        lines.append("Top IPs in ASN:")
        try:
            ips = self.cache.list_ips_in_asn(asn, limit=50)
            if not ips:
                lines.append("  (no rows)")
            else:
                for r in ips:
                    lines.append(f"  {r['ip']} ban_total={r['ban_count_total']} bans={r['bans']} fails={r['fails']} last_seen={fmt_epoch_utc(r['last_seen_ts'])}")
        except Exception as e:
            lines.append(f"  error: {e}")
        return lines

    def get_events_lines(self, max_lines: int = 200) -> List[str]:
        out: List[str] = []
        for ev in list(self.events)[-max_lines:]:
            if ev.kind in ("INFO", "ERR"):
                out.append(f"{fmt_epoch_utc(ev.ts)} {ev.kind} {ev.msg}")
            else:
                j = f" jail={ev.jail}" if ev.jail else ""
                out.append(f"{fmt_epoch_utc(ev.ts)} {ev.src} {ev.kind} {ev.ip}{j}")
        return out
