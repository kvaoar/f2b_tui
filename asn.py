#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from model import ASNInfo
from utils import now_ts


def cymru_bulk_lookup_nc(
    ips: Sequence[str],
    host: str = "whois.cymru.com",
    timeout_s: float = 4.0,
) -> Dict[str, ASNInfo]:
    """
    Query Team Cymru whois in bulk mode using nc to TCP/43.
    No empty calls: if ips is empty, returns {} without invoking subprocess.
    The response format (bulk):
      non-verbose: AS | IP | CC | Registry | Allocated | AS Name
      verbose    : AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
    We use: begin + verbose
    """
    if not ips:
        return {}
    asked = [ip.strip() for ip in ips if ip.strip()]
    if not asked:
        return {}

    q_lines = ["begin", "verbose"]
    q_lines.extend(asked)
    q_lines.append("end")
    query = "\n".join(q_lines) + "\n"

    nci = ["nc", "-w", str(int(timeout_s)), host, "43"]
    try:
        proc = subprocess.run(
            nci,
            input=query.encode("ascii", errors="ignore"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=float(timeout_s) + 3.0,
            check=False,
        )
    except Exception:
        return {}

    if proc.returncode != 0:
        return {}

    text = proc.stdout.decode("utf-8", errors="replace").splitlines()
    out: Dict[str, ASNInfo] = {}
    fetched = now_ts()
    for line in text:
        # skip headers, comments
        if not line or line.startswith("AS") or line.startswith("Bulk mode") or line.startswith("#"):
            continue
        # non-verbose: "13335 | 1.2.3.4 | US | arin | 2010-01-01 | CLOUDFLARENET - Cloudflare, Inc., US"
        # verbose    : "13335 | 1.2.3.4 | 1.2.3.0/24 | US | arin | 2010-01-01 | CLOUDFLARENET - Cloudflare, Inc., US"
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 6:
            continue
        asn = parts[0]
        ip = parts[1]
        if len(parts) >= 7:
            # verbose: parts[2] is BGP prefix
            cc = parts[3]
            as_name = parts[6]
        else:
            # non-verbose
            cc = parts[2]
            as_name = parts[5]
        if ip:
            out[ip] = ASNInfo(asn=str(asn), cc=str(cc), as_name=str(as_name), fetched_ts=fetched)
    return out
