#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import sqlite3
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from model import ASNInfo, Event
from utils import now_ts, ip_to_subnet


SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS ip_cache (
    ip TEXT PRIMARY KEY,
    first_seen_ts INTEGER NOT NULL,
    last_seen_ts INTEGER NOT NULL,
    fails INTEGER NOT NULL DEFAULT 0,
    oks INTEGER NOT NULL DEFAULT 0,
    bans INTEGER NOT NULL DEFAULT 0,
    unbans INTEGER NOT NULL DEFAULT 0,
    last_event TEXT NOT NULL DEFAULT '',
    last_jail TEXT NOT NULL DEFAULT '',
    last_ban_ts INTEGER NULL,
    last_ban_jail TEXT NOT NULL DEFAULT '',
    ban_count_total INTEGER NOT NULL DEFAULT 0,
    provider_asn TEXT NOT NULL DEFAULT '',
    provider_cc TEXT NOT NULL DEFAULT '',
    provider_name TEXT NOT NULL DEFAULT '',
    provider_fetched_ts INTEGER NULL
);

CREATE TABLE IF NOT EXISTS subnet_cache (
    subnet TEXT PRIMARY KEY,
    prefix INTEGER NOT NULL,
    first_seen_ts INTEGER NOT NULL,
    last_seen_ts INTEGER NOT NULL,
    fails INTEGER NOT NULL DEFAULT 0,
    bans INTEGER NOT NULL DEFAULT 0,
    unbans INTEGER NOT NULL DEFAULT 0,
    unique_ips INTEGER NOT NULL DEFAULT 0,
    last_ip TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS subnet_ip (
    subnet TEXT NOT NULL,
    ip TEXT NOT NULL,
    first_seen_ts INTEGER NOT NULL,
    last_seen_ts INTEGER NOT NULL,
    PRIMARY KEY (subnet, ip)
);

CREATE TABLE IF NOT EXISTS asn_cache (
    ip TEXT PRIMARY KEY,
    asn TEXT NOT NULL,
    cc TEXT NOT NULL,
    as_name TEXT NOT NULL,
    fetched_ts INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS bips_import_state (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
"""


class CacheDB:
    def __init__(self, path: str):
        self.path = path
        self.con = sqlite3.connect(self.path, timeout=3.0)
        self.con.row_factory = sqlite3.Row
        self.con.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self) -> None:
        self.con.executescript(SCHEMA_SQL)
        self.con.commit()

    def close(self) -> None:
        try:
            self.con.close()
        except Exception:
            pass

    def set_state(self, k: str, v: str) -> None:
        self.con.execute(
            "INSERT INTO bips_import_state(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (k, v),
        )

    def get_state(self, k: str) -> Optional[str]:
        r = self.con.execute("SELECT v FROM bips_import_state WHERE k=?", (k,)).fetchone()
        return str(r["v"]) if r else None

    def upsert_ip_event(self, ip: str, ev_ts: int, kind: str, jail: str, show_ok: bool, subnet_prefix: int) -> None:
        # Update ip_cache counters. kind: FAIL/OK/BAN/UNBAN
        inc_f = 1 if kind == "FAIL" else 0
        inc_o = 1 if kind == "OK" else 0
        inc_b = 1 if kind == "BAN" else 0
        inc_u = 1 if kind == "UNBAN" else 0
        # if show_ok is false, do not increment OK in cache to reduce noise (but still allowed to store)
        if not show_ok:
            inc_o = 0

        self.con.execute(
            """
            INSERT INTO ip_cache(ip, first_seen_ts, last_seen_ts, fails, oks, bans, unbans, last_event, last_jail)
            VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(ip) DO UPDATE SET
                last_seen_ts=excluded.last_seen_ts,
                fails=fails + ?,
                oks=oks + ?,
                bans=bans + ?,
                unbans=unbans + ?,
                last_event=excluded.last_event,
                last_jail=excluded.last_jail
            """,
            (
                ip,
                ev_ts,
                ev_ts,
                inc_f,
                inc_o,
                inc_b,
                inc_u,
                kind,
                jail or "",
                inc_f,
                inc_o,
                inc_b,
                inc_u,
            ),
        )
        # subnet aggregate
        subnet = ip_to_subnet(ip, subnet_prefix)
        self._upsert_subnet_ip(subnet, subnet_prefix, ip, ev_ts)
        self._upsert_subnet_counters(subnet, subnet_prefix, ev_ts, inc_f, inc_b, inc_u, ip)

    def _upsert_subnet_ip(self, subnet: str, prefix: int, ip: str, ts: int) -> None:
        self.con.execute(
            """
            INSERT INTO subnet_ip(subnet, ip, first_seen_ts, last_seen_ts)
            VALUES(?,?,?,?)
            ON CONFLICT(subnet, ip) DO UPDATE SET
                last_seen_ts=CASE WHEN excluded.last_seen_ts>subnet_ip.last_seen_ts THEN excluded.last_seen_ts ELSE subnet_ip.last_seen_ts END
            """,
            (subnet, ip, ts, ts),
        )

    def _upsert_subnet_counters(self, subnet: str, prefix: int, ts: int, inc_f: int, inc_b: int, inc_u: int, last_ip: str) -> None:
        # unique_ips must be updated if subnet_ip newly inserted; easiest: recompute unique count for subnet occasionally.
        self.con.execute(
            """
            INSERT INTO subnet_cache(subnet, prefix, first_seen_ts, last_seen_ts, fails, bans, unbans, unique_ips, last_ip)
            VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(subnet) DO UPDATE SET
                last_seen_ts=CASE WHEN excluded.last_seen_ts>subnet_cache.last_seen_ts THEN excluded.last_seen_ts ELSE subnet_cache.last_seen_ts END,
                fails=fails + ?,
                bans=bans + ?,
                unbans=unbans + ?,
                last_ip=excluded.last_ip
            """,
            (subnet, prefix, ts, ts, inc_f, inc_b, inc_u, 0, last_ip, inc_f, inc_b, inc_u),
        )

    def refresh_subnet_unique_counts(self) -> None:
        # recompute unique_ips for all subnets
        rows = self.con.execute("SELECT subnet FROM subnet_cache").fetchall()
        for r in rows:
            subnet = str(r["subnet"])
            c = self.con.execute("SELECT COUNT(*) AS n FROM subnet_ip WHERE subnet=?", (subnet,)).fetchone()
            n = int(c["n"] or 0)
            self.con.execute("UPDATE subnet_cache SET unique_ips=? WHERE subnet=?", (n, subnet))

    def upsert_imported_bips(self, ip: str, ban_count_total: int, last_ban_ts: Optional[int], last_ban_jail: str, subnet_prefix: int) -> None:
        ts = now_ts()
        self.con.execute(
            """
            INSERT INTO ip_cache(ip, first_seen_ts, last_seen_ts, ban_count_total, last_ban_ts, last_ban_jail)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(ip) DO UPDATE SET
                ban_count_total=CASE WHEN excluded.ban_count_total>ip_cache.ban_count_total THEN excluded.ban_count_total ELSE ip_cache.ban_count_total END,
                last_ban_ts=CASE
                    WHEN excluded.last_ban_ts IS NULL THEN ip_cache.last_ban_ts
                    WHEN ip_cache.last_ban_ts IS NULL THEN excluded.last_ban_ts
                    WHEN excluded.last_ban_ts>ip_cache.last_ban_ts THEN excluded.last_ban_ts
                    ELSE ip_cache.last_ban_ts
                END,
                last_ban_jail=CASE
                    WHEN excluded.last_ban_ts IS NULL THEN ip_cache.last_ban_jail
                    WHEN ip_cache.last_ban_ts IS NULL THEN excluded.last_ban_jail
                    WHEN excluded.last_ban_ts>ip_cache.last_ban_ts THEN excluded.last_ban_jail
                    ELSE ip_cache.last_ban_jail
                END,
                last_seen_ts=CASE
                    WHEN excluded.last_ban_ts IS NULL THEN ip_cache.last_seen_ts
                    WHEN excluded.last_ban_ts>ip_cache.last_seen_ts THEN excluded.last_ban_ts
                    ELSE ip_cache.last_seen_ts
                END
            """,
            (ip, ts, ts, int(ban_count_total or 0), last_ban_ts, last_ban_jail or ""),
        )
        if last_ban_ts is not None:
            subnet = ip_to_subnet(ip, subnet_prefix)
            self._upsert_subnet_ip(subnet, subnet_prefix, ip, int(last_ban_ts))
            self.con.execute(
                """
                INSERT INTO subnet_cache(subnet, prefix, first_seen_ts, last_seen_ts, unique_ips, last_ip)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(subnet) DO UPDATE SET
                    last_seen_ts=CASE WHEN excluded.last_seen_ts>subnet_cache.last_seen_ts THEN excluded.last_seen_ts ELSE subnet_cache.last_seen_ts END,
                    last_ip=excluded.last_ip
                """,
                (subnet, subnet_prefix, int(last_ban_ts), int(last_ban_ts), 0, ip),
            )

    def upsert_asn_info(self, ip_to_asn: Dict[str, ASNInfo]) -> Tuple[int, int]:
        """
        Writes to asn_cache and duplicates into ip_cache provider_*.
        Returns (asked, written).
        """
        asked = len(ip_to_asn)
        written = 0
        for ip, info in ip_to_asn.items():
            self.con.execute(
                """
                INSERT INTO asn_cache(ip, asn, cc, as_name, fetched_ts)
                VALUES(?,?,?,?,?)
                ON CONFLICT(ip) DO UPDATE SET
                    asn=excluded.asn,
                    cc=excluded.cc,
                    as_name=excluded.as_name,
                    fetched_ts=excluded.fetched_ts
                """,
                (ip, info.asn, info.cc, info.as_name, int(info.fetched_ts)),
            )
            self.con.execute(
                """
                UPDATE ip_cache
                SET provider_asn=?, provider_cc=?, provider_name=?, provider_fetched_ts=?
                WHERE ip=?
                """,
                (info.asn, info.cc, info.as_name, int(info.fetched_ts), ip),
            )
            written += 1
        return asked, written

    def get_ip_row(self, ip: str) -> Optional[sqlite3.Row]:
        return self.con.execute("SELECT * FROM ip_cache WHERE ip=?", (ip,)).fetchone()

    def get_subnet_row(self, subnet: str) -> Optional[sqlite3.Row]:
        return self.con.execute("SELECT * FROM subnet_cache WHERE subnet=?", (subnet,)).fetchone()

    def get_ip_events_from_cache(self, ip: str) -> List[sqlite3.Row]:
        # no persistent event log by design (in-memory only)
        return []

    def list_realtime_seed_ips(self, n: int) -> List[str]:
        if n <= 0:
            return []
        rows = self.con.execute(
            "SELECT ip FROM ip_cache ORDER BY last_seen_ts DESC LIMIT ?",
            (int(n),),
        ).fetchall()
        return [str(r["ip"]) for r in rows]

    def list_ip_cache(self, search: str, limit: int = 500) -> List[sqlite3.Row]:
        s = f"%{search.lower()}%"
        if search:
            q = """
                SELECT * FROM ip_cache
                WHERE lower(ip) LIKE ? OR lower(provider_name) LIKE ? OR lower(provider_asn) LIKE ?
                ORDER BY ban_count_total DESC, bans DESC, fails DESC, last_seen_ts DESC
                LIMIT ?
            """
            return list(self.con.execute(q, (s, s, s, int(limit))).fetchall())
        q = """
            SELECT * FROM ip_cache
            ORDER BY ban_count_total DESC, bans DESC, fails DESC, last_seen_ts DESC
            LIMIT ?
        """
        return list(self.con.execute(q, (int(limit),)).fetchall())

    def list_top_subnets(self, top_n: int, search: str) -> List[sqlite3.Row]:
        s = f"%{search.lower()}%"
        if search:
            q = """
                SELECT * FROM subnet_cache
                WHERE lower(subnet) LIKE ?
                ORDER BY (bans + fails) DESC, unique_ips DESC, last_seen_ts DESC
                LIMIT ?
            """
            return list(self.con.execute(q, (s, int(top_n))).fetchall())
        q = """
            SELECT * FROM subnet_cache
            ORDER BY (bans + fails) DESC, unique_ips DESC, last_seen_ts DESC
            LIMIT ?
        """
        return list(self.con.execute(q, (int(top_n),)).fetchall())

    def list_asn_summary(self, search: str, limit: int = 200) -> List[sqlite3.Row]:
        s = f"%{search.lower()}%"
        if search:
            q = """
                SELECT provider_asn AS asn,
                       MAX(provider_name) AS as_name,
                       MAX(provider_cc) AS cc,
                       COUNT(*) AS ip_count,
                       SUM(ban_count_total) AS ban_total_sum,
                       SUM(bans) AS bans_sum,
                       SUM(fails) AS fails_sum,
                       MAX(provider_fetched_ts) AS last_fetch_ts
                FROM ip_cache
                WHERE provider_asn <> '' AND (lower(provider_asn) LIKE ? OR lower(provider_name) LIKE ? OR lower(provider_cc) LIKE ?)
                GROUP BY provider_asn
                ORDER BY ban_total_sum DESC, bans_sum DESC, fails_sum DESC, ip_count DESC
                LIMIT ?
            """
            return list(self.con.execute(q, (s, s, s, int(limit))).fetchall())
        q = """
            SELECT provider_asn AS asn,
                   MAX(provider_name) AS as_name,
                   MAX(provider_cc) AS cc,
                   COUNT(*) AS ip_count,
                   SUM(ban_count_total) AS ban_total_sum,
                   SUM(bans) AS bans_sum,
                   SUM(fails) AS fails_sum,
                   MAX(provider_fetched_ts) AS last_fetch_ts
            FROM ip_cache
            WHERE provider_asn <> ''
            GROUP BY provider_asn
            ORDER BY ban_total_sum DESC, bans_sum DESC, fails_sum DESC, ip_count DESC
            LIMIT ?
        """
        return list(self.con.execute(q, (int(limit),)).fetchall())

    def list_ips_in_subnet(self, subnet: str, limit: int = 50) -> List[sqlite3.Row]:
        q = """
            SELECT i.*
            FROM subnet_ip s
            JOIN ip_cache i ON i.ip = s.ip
            WHERE s.subnet = ?
            ORDER BY i.ban_count_total DESC, i.bans DESC, i.fails DESC, s.last_seen_ts DESC
            LIMIT ?
        """
        return list(self.con.execute(q, (subnet, int(limit))).fetchall())

    def list_ips_in_asn(self, asn: str, limit: int = 50) -> List[sqlite3.Row]:
        q = """
            SELECT *
            FROM ip_cache
            WHERE provider_asn = ?
            ORDER BY ban_count_total DESC, bans DESC, fails DESC, last_seen_ts DESC
            LIMIT ?
        """
        return list(self.con.execute(q, (asn, int(limit))).fetchall())
