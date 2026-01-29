#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import sqlite3
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


def _connect_ro(path: str) -> sqlite3.Connection:
    # SQLite URI for read-only
    uri = f"file:{path}?mode=ro"
    con = sqlite3.connect(uri, uri=True, timeout=3.0)
    con.row_factory = sqlite3.Row
    return con


def _table_exists(con: sqlite3.Connection, name: str) -> bool:
    row = con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1", (name,)).fetchone()
    return row is not None


def _columns(con: sqlite3.Connection, table: str) -> set[str]:
    cols = set()
    for r in con.execute(f"PRAGMA table_info({table})"):
        cols.add(str(r[1]))
    return cols


def source_fingerprint(path: str) -> Tuple[int, int]:
    st = os.stat(path)
    return (int(st.st_mtime), int(st.st_size))


def fetch_top_bips(path: str, limit: int = 200) -> List[sqlite3.Row]:
    """
    Returns rows with at least: ip, jail, timeofban, bantime, bancount
    Tries bips first, falls back to bans aggregated if needed.
    """
    con = _connect_ro(path)
    try:
        if _table_exists(con, "bips"):
            cols = _columns(con, "bips")
            # Prefer standard columns
            need = {"ip", "jail", "timeofban"}
            if not need.issubset(cols):
                raise RuntimeError("bips table exists but missing required columns")
            # bancount may be absent in some versions; compute if needed
            if "bancount" in cols:
                q = """
                    SELECT ip, jail, timeofban, bantime, bancount
                    FROM bips
                    ORDER BY bancount DESC, timeofban DESC
                    LIMIT ?
                """
                return list(con.execute(q, (limit,)).fetchall())
            else:
                q = """
                    SELECT ip, jail, MAX(timeofban) AS timeofban, MAX(bantime) AS bantime, COUNT(*) AS bancount
                    FROM bips
                    GROUP BY ip
                    ORDER BY bancount DESC, timeofban DESC
                    LIMIT ?
                """
                return list(con.execute(q, (limit,)).fetchall())
        if _table_exists(con, "bans"):
            cols = _columns(con, "bans")
            need = {"ip", "jail", "timeofban"}
            if not need.issubset(cols):
                raise RuntimeError("bans table exists but missing required columns")
            q = """
                SELECT ip,
                       (SELECT jail FROM bans b2 WHERE b2.ip=b1.ip ORDER BY timeofban DESC LIMIT 1) AS jail,
                       MAX(timeofban) AS timeofban,
                       (SELECT bantime FROM bans b3 WHERE b3.ip=b1.ip ORDER BY timeofban DESC LIMIT 1) AS bantime,
                       COUNT(*) AS bancount
                FROM bans b1
                GROUP BY ip
                ORDER BY bancount DESC, timeofban DESC
                LIMIT ?
            """
            return list(con.execute(q, (limit,)).fetchall())
        raise RuntimeError("No bips/bans table found in fail2ban sqlite")
    finally:
        con.close()


def fetch_ip_history_bips(path: str, ip: str, limit: Optional[int] = None) -> List[sqlite3.Row]:
    """
    Returns per-ban history rows: jail,timeofban,bantime,bancount(if available or 1)
    """
    con = _connect_ro(path)
    try:
        limit_clause = " LIMIT ?" if limit is not None else ""
        if _table_exists(con, "bips"):
            cols = _columns(con, "bips")
            if {"ip", "jail", "timeofban"}.issubset(cols):
                if "bancount" in cols:
                    q = """
                        SELECT jail, timeofban, bantime, bancount
                        FROM bips
                        WHERE ip=?
                        ORDER BY timeofban DESC
                    """
                    q = q.rstrip() + limit_clause
                    params = (ip,) if limit is None else (ip, limit)
                    return list(con.execute(q, params).fetchall())
                else:
                    q = """
                        SELECT jail, timeofban, bantime, 1 AS bancount
                        FROM bips
                        WHERE ip=?
                        ORDER BY timeofban DESC
                    """
                    q = q.rstrip() + limit_clause
                    params = (ip,) if limit is None else (ip, limit)
                    return list(con.execute(q, params).fetchall())
        if _table_exists(con, "bans"):
            cols = _columns(con, "bans")
            if {"ip", "jail", "timeofban"}.issubset(cols):
                q = """
                    SELECT jail, timeofban, bantime, 1 AS bancount
                    FROM bans
                    WHERE ip=?
                    ORDER BY timeofban DESC
                """
                q = q.rstrip() + limit_clause
                params = (ip,) if limit is None else (ip, limit)
                return list(con.execute(q, params).fetchall())
        return []
    finally:
        con.close()


def import_bips_aggregates(path: str) -> Dict[str, Dict[str, object]]:
    """
    Returns dict ip -> {ban_count_total:int, last_ban_ts:int, last_ban_jail:str, last_ban_bantime:int}
    Used for bootstrapping cache.
    """
    con = _connect_ro(path)
    try:
        if _table_exists(con, "bips"):
            cols = _columns(con, "bips")
            if not {"ip", "jail", "timeofban"}.issubset(cols):
                raise RuntimeError("bips table missing required columns")
            # If bancount exists per-row, total is SUM(bancount); else COUNT(*)
            if "bancount" in cols:
                q = """
                    SELECT ip,
                           SUM(bancount) AS ban_count_total,
                           MAX(timeofban) AS last_ban_ts
                    FROM bips
                    GROUP BY ip
                """
            else:
                q = """
                    SELECT ip,
                           COUNT(*) AS ban_count_total,
                           MAX(timeofban) AS last_ban_ts
                    FROM bips
                    GROUP BY ip
                """
            rows = con.execute(q).fetchall()
            out: Dict[str, Dict[str, object]] = {}
            for r in rows:
                ip = str(r["ip"])
                last_ban_ts = int(r["last_ban_ts"]) if r["last_ban_ts"] is not None else None
                # jail + bantime for the last ban
                jail_row = con.execute(
                    "SELECT jail, bantime FROM bips WHERE ip=? ORDER BY timeofban DESC LIMIT 1",
                    (ip,),
                ).fetchone()
                last_jail = str(jail_row["jail"]) if jail_row and jail_row["jail"] is not None else ""
                last_bantime = int(jail_row["bantime"]) if jail_row and jail_row["bantime"] is not None else 0
                out[ip] = {
                    "ban_count_total": int(r["ban_count_total"] or 0),
                    "last_ban_ts": last_ban_ts,
                    "last_ban_jail": last_jail,
                    "last_ban_bantime": last_bantime,
                }
            return out
        if _table_exists(con, "bans"):
            cols = _columns(con, "bans")
            if not {"ip", "jail", "timeofban"}.issubset(cols):
                raise RuntimeError("bans table missing required columns")
            q = """
                SELECT ip,
                       COUNT(*) AS ban_count_total,
                       MAX(timeofban) AS last_ban_ts
                FROM bans
                GROUP BY ip
            """
            rows = con.execute(q).fetchall()
            out: Dict[str, Dict[str, object]] = {}
            for r in rows:
                ip = str(r["ip"])
                last_ban_ts = int(r["last_ban_ts"]) if r["last_ban_ts"] is not None else None
                jail_row = con.execute(
                    "SELECT jail, bantime FROM bans WHERE ip=? ORDER BY timeofban DESC LIMIT 1",
                    (ip,),
                ).fetchone()
                last_jail = str(jail_row["jail"]) if jail_row and jail_row["jail"] is not None else ""
                last_bantime = int(jail_row["bantime"]) if jail_row and jail_row["bantime"] is not None else 0
                out[ip] = {
                    "ban_count_total": int(r["ban_count_total"] or 0),
                    "last_ban_ts": last_ban_ts,
                    "last_ban_jail": last_jail,
                    "last_ban_bantime": last_bantime,
                }
            return out
        raise RuntimeError("No bips/bans table found in fail2ban sqlite")
    finally:
        con.close()
