#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import time
from typing import Iterator, Optional


class TailFile:
    """
    A minimal "tail -F": follows a file across rotation.
    Reads new lines since last position. Uses inode tracking and reopens if rotated.
    """
    def __init__(self, path: str, start_at_end: bool = True, poll_sleep: float = 0.05):
        self.path = path
        self.start_at_end = start_at_end
        self.poll_sleep = poll_sleep
        self._fp: Optional[object] = None
        self._inode: Optional[int] = None
        self._pos: int = 0
        self._opened_once: bool = False

    def _try_open(self) -> None:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return
        inode = int(getattr(st, "st_ino", 0))
        if self._fp is None:
            self._fp = open(self.path, "r", encoding="utf-8", errors="replace")
            self._inode = inode
            if self.start_at_end and not self._opened_once:
                self._fp.seek(0, os.SEEK_END)
                self._pos = self._fp.tell()
                self._opened_once = True
            else:
                self._fp.seek(self._pos, os.SEEK_SET)
            return
        # already open; check rotation
        if self._inode is None or inode != self._inode:
            try:
                self._fp.close()
            except Exception:
                pass
            self._fp = open(self.path, "r", encoding="utf-8", errors="replace")
            self._inode = inode
            self._pos = 0
            self._fp.seek(0, os.SEEK_SET)

    def read_available_lines(self, max_lines: int = 2000) -> list[str]:
        self._try_open()
        if self._fp is None:
            return []
        out: list[str] = []
        try:
            while len(out) < max_lines:
                line = self._fp.readline()
                if not line:
                    break
                out.append(line.rstrip("\n"))
            self._pos = self._fp.tell()
        except Exception:
            # reset on read errors
            try:
                self._fp.close()
            except Exception:
                pass
            self._fp = None
            self._inode = None
        return out
