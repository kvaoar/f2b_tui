#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
from typing import Optional, Tuple


def now_ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def now_utc_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def fmt_epoch_utc(ts: Optional[int]) -> str:
    if ts is None:
        return "—"
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def clamp(n: int, lo: int, hi: int) -> int:
    if n < lo:
        return lo
    if n > hi:
        return hi
    return n


def ip_to_subnet(ip: str, prefix: int) -> str:
    ip_obj = ipaddress.ip_address(ip)
    if ip_obj.version != 4:
        raise ValueError("IPv4 only")
    net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    return str(net)


def ip_plausible_ipv4(ip: str) -> bool:
    try:
        o = ipaddress.ip_address(ip)
        return o.version == 4
    except Exception:
        return False


def human_int(n: int) -> str:
    return f"{n:,}".replace(",", " ")


def safe_str(s: object) -> str:
    try:
        return str(s)
    except Exception:
        return repr(s)
