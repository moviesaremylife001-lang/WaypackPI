# waypack/logger.py
from __future__ import annotations
from datetime import datetime
import sys

class RunLogger:
    def __init__(self, path: str = "run.log", mirror_stdout: bool = False):
        self.path = path
        self._fh = open(path, "w", encoding="utf-8", errors="replace")
        self._mirror = mirror_stdout
        self._counters = {
            "HTML_ORIG": 0, "HTML_KEPT": 0, "HTML_SKIPPED": 0,
            "IMG_ORIG": 0, "IMG_KEPT": 0, "IMG_SKIPPED": 0,
            "FIND_ORIG": 0, "FIND_DEDUPED": 0, "FIND_KEPT": 0,
            "EMB_ORIG": 0, "EMB_DEDUPED": 0, "EMB_KEPT": 0,
            "EXIF_ORIG": 0, "EXIF_DEDUPED": 0, "EXIF_KEPT": 0,
        }

    def log(self, level: str, phase: str, url: str = "", **kv):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        parts = [f"[{ts}] {level} {phase}"]
        if url:
            parts.append(f"url={url}")
        for k, v in kv.items():
            parts.append(f"{k}={v}")
        line = " ".join(parts) + "\n"
        self._fh.write(line)
        if self._mirror:
            sys.stderr.write(line)

    def count(self, key: str, inc: int = 1):
        if key in self._counters:
            self._counters[key] += inc

    def summary(self):
        s = " ".join(f"{k}={v}" for k, v in self._counters.items())
        self._fh.write(f"[SUMMARY] {s}\n")
        if self._mirror:
            sys.stderr.write(f"[SUMMARY] {s}\n")

    def close(self):
        try:
            self.summary()
        finally:
            self._fh.close()
