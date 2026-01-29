#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re
from typing import Optional, Tuple

from utils import ip_plausible_ipv4

IP_RE = re.compile(r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})")

SSH_FAIL_RE = re.compile(r"\b(Failed password|Invalid user|authentication failure)\b")
SSH_OK_RE = re.compile(r"\b(Accepted (?:password|publickey))\b")

# Example fail2ban lines:
# 2026-01-29 12:34:56,789 fail2ban.actions [1234]: NOTICE [sshd] Ban 1.2.3.4
# 2026-01-29 12:34:56,789 fail2ban.actions [1234]: NOTICE [sshd] Unban 1.2.3.4
F2B_JAIL_RE = re.compile(r"\[(?P<jail>[A-Za-z0-9_.:-]+)\]")
F2B_BAN_RE = re.compile(r"\bBan\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b")
F2B_UNBAN_RE = re.compile(r"\bUnban\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b")


def is_ipv4_plausible(ip: str) -> bool:
    return ip_plausible_ipv4(ip)


def parse_ssh_line(line: str) -> Optional[Tuple[str, str]]:
    """
    Returns (ip, kind) where kind in {"FAIL","OK"} or None.
    """
    m = IP_RE.search(line)
    if not m:
        return None
    ip = m.group("ip")
    if not is_ipv4_plausible(ip):
        return None
    if SSH_FAIL_RE.search(line):
        return (ip, "FAIL")
    if SSH_OK_RE.search(line):
        return (ip, "OK")
    return None


def parse_f2b_line(line: str) -> Optional[Tuple[str, str, str]]:
    """
    Returns (ip, kind, jail) where kind in {"BAN","UNBAN"} or None.
    """
    jail = ""
    mj = F2B_JAIL_RE.search(line)
    if mj:
        jail = mj.group("jail")
    mb = F2B_BAN_RE.search(line)
    if mb:
        ip = mb.group("ip")
        if is_ipv4_plausible(ip):
            return (ip, "BAN", jail)
    mu = F2B_UNBAN_RE.search(line)
    if mu:
        ip = mu.group("ip")
        if is_ipv4_plausible(ip):
            return (ip, "UNBAN", jail)
    return None
