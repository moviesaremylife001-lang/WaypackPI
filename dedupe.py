# waypack/dedupe.py
from __future__ import annotations
from collections import deque
from datetime import datetime, timedelta
from typing import Hashable

class SeenWindow:
    """Sliding window deduper keyed by a hashable. Keeps last N days of keys."""
    def __init__(self, days: int = 60):
        self.days = max(1, days)
        self._q = deque()  # (date, key)
        self._set = set()

    def keep(self, day_str: str, key: Hashable) -> bool:
        """Return True if key not seen in window; record it. day_str = 'YYYY-MM-DD'."""
        self._expire(day_str)
        if key in self._set:
            return False
        self._set.add(key)
        self._q.append((day_str, key))
        return True

    def _expire(self, day_str: str):
        try:
            cur = datetime.strptime(day_str, "%Y-%m-%d")
        except Exception:
            # If parse fails, don't expire to avoid accidental data loss
            return
        cutoff = cur - timedelta(days=self.days)
        while self._q:
            d, k = self._q[0]
            try:
                dd = datetime.strptime(d, "%Y-%m-%d")
            except Exception:
                dd = cur  # be conservative
            if dd >= cutoff:
                break
            self._q.popleft()
            self._set.discard(k)
