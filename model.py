#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Tuple


@dataclass
class IPStats:
    ip: str
    first_seen_ts: int
    last_seen_ts: int
    fails: int = 0
    oks: int = 0
    bans: int = 0
    unbans: int = 0
    last_event: str = ""
    last_jail: str = ""
    last_ban_ts: Optional[int] = None
    last_ban_jail: str = ""
    ban_count_total: int = 0
    provider_asn: str = ""
    provider_cc: str = ""
    provider_name: str = ""
    provider_fetched_ts: Optional[int] = None


@dataclass
class Event:
    ts: int
    src: str            # "auth" | "f2b" | "poll" | "sys"
    kind: str           # "FAIL" | "OK" | "BAN" | "UNBAN" | "INFO" | "ERR"
    ip: str
    jail: str = ""
    msg: str = ""


@dataclass
class ASNInfo:
    asn: str
    cc: str
    as_name: str
    fetched_ts: int


@dataclass
class ListState:
    tab: str
    cursor: int = 0
    offset: int = 0
    search: str = ""


@dataclass
class DetailsState:
    open: bool = False
    title: str = ""
    lines: List[str] = field(default_factory=list)
    cursor: int = 0
    offset: int = 0
    search: str = ""  # not used yet, reserved
