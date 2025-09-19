# waypack/fetcher.py
from __future__ import annotations
import time
import requests
from dataclasses import dataclass

WAYBACK_PREFIX = "https://web.archive.org/web"

@dataclass
class FetchResult:
    ok: bool
    status: int
    mime: str | None
    data: bytes | None
    url: str
    error: str | None = None
    bytes_read: int = 0

class Fetcher:
    def __init__(self, rps: float = 2.0, timeout: int = 15, max_bytes: int = 5_000_000, retries: int = 3, user_agent: str | None = None):
        self.rps = max(0.1, rps)
        self._min_interval = 1.0 / self.rps
        self._last = 0.0
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.retries = retries
        self.sess = requests.Session()
        if user_agent:
            self.sess.headers.update({"User-Agent": user_agent})

    def _throttle(self):
        now = time.time()
        delta = now - self._last
        if delta < self._min_interval:
            time.sleep(self._min_interval - delta)
        self._last = time.time()

    @staticmethod
    def to_archive_url(timestamp: str, original: str, id_mode: bool = True) -> str:
        """Construct a Wayback replay URL for given timestamp+original."""
        suffix = "id_" if id_mode else ""
        return f"{WAYBACK_PREFIX}/{timestamp}{suffix}/{original}"

    def get(self, url: str) -> FetchResult:
        """Stream a URL with caps + retries."""
        error = None
        for attempt in range(self.retries):
            try:
                self._throttle()
                with self.sess.get(url, stream=True, timeout=self.timeout) as r:
                    mime = r.headers.get("Content-Type")
                    status = r.status_code
                    if status != 200:
                        return FetchResult(False, status, mime, None, url, error=None, bytes_read=0)
                    chunks = []
                    total = 0
                    for chunk in r.iter_content(chunk_size=8192):
                        if not chunk:
                            continue
                        total += len(chunk)
                        if total > self.max_bytes:
                            return FetchResult(False, status, mime, None, url, error="too_large", bytes_read=total)
                        chunks.append(chunk)
                    data = b"".join(chunks)
                    return FetchResult(True, status, mime.split(";")[0].strip() if mime else None, data, url, None, total)
            except Exception as e:
                error = str(e)
                time.sleep(1.5 * (attempt + 1))
        return FetchResult(False, 0, None, None, url, error=error or "fetch_failed", bytes_read=0)
