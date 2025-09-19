# waypack/cdx_client.py
from __future__ import annotations
import time
import requests
from typing import Iterable, Dict, Any

CDX_URL = "https://web.archive.org/cdx/search/cdx"

class CDXClient:
    def __init__(self, rps: float = 2.0, session: requests.Session | None = None, user_agent: str | None = None):
        self.rps = max(0.1, rps)
        self._min_interval = 1.0 / self.rps
        self._last = 0.0
        self.sess = session or requests.Session()
        if user_agent:
            self.sess.headers.update({"User-Agent": user_agent})

    def _throttle(self):
        now = time.time()
        delta = now - self._last
        if delta < self._min_interval:
            time.sleep(self._min_interval - delta)
        self._last = time.time()

    def query_daily_sample(
        self,
        domain: str,
        dt_from: str,
        dt_to: str,
        statuscode: str = "200",
        mimetype: str = "text/html",
        limit: int | None = None,
        retries: int = 3,
        timeout: int = 15,
    ) -> Iterable[Dict[str, Any]]:
        """
        Yield 1 record per day (earliest in day) for domain (includes subdomains).
        Fields: timestamp, original, statuscode, mimetype, digest, length
        """
        params = {
            "url": domain,
            "matchType": "domain",
            "from": dt_from.replace("-", ""),
            "to": dt_to.replace("-", ""),
            "output": "json",
            "fl": "timestamp,original,statuscode,mimetype,digest,length",
            "filter": [f"statuscode:{statuscode}", f"mimetype:{mimetype}"],
            "collapse": "timestamp:8",  # YYYYMMDD
            "showResumeKey": "true",
        }
        resume = None
        rows = 0
        while True:
            if resume:
                params["resumeKey"] = resume
            # Throttle + request with basic retry
            for attempt in range(retries):
                try:
                    self._throttle()
                    resp = self.sess.get(CDX_URL, params=params, timeout=timeout)
                    resp.raise_for_status()
                    data = resp.json()
                    break
                except Exception:
                    if attempt + 1 == retries:
                        raise
                    time.sleep(1.5 * (attempt + 1))
            if not data:
                return
            # First row is header
            header, *records = data
            for rec in records:
                if isinstance(rec, list) and len(rec) >= 6:
                    out = {
                        "timestamp": rec[0],
                        "original": rec[1],
                        "statuscode": rec[2],
                        "mimetype": rec[3],
                        "digest": rec[4],
                        "length": rec[5],
                    }
                    yield out
                    rows += 1
                    if limit and rows >= limit:
                        return
                elif isinstance(rec, str) and rec.startswith("resumeKey:"):
                    resume = rec.split(":", 1)[1].strip()
                else:
                    # ignore unexpected rows
                    pass
            # If we didn’t get a resume key, we’re done
            if not any(isinstance(r, str) and r.startswith("resumeKey:") for r in data[1:]):
                return
