# waypack/exporters.py
from __future__ import annotations
import csv, json, hashlib
from typing import Dict, Any, Iterable, Tuple
from .dedupe import SeenWindow

def sha256_hex(b: bytes) -> str:
    h = hashlib.sha256(); h.update(b); return h.hexdigest()

# --- Findings (regex hits) ---

def write_findings_csv(path: str, rows: Iterable[Dict[str, Any]]):
    cols = ["date","url","status","mime","bytes","rule_id","family","match","ctx_left","ctx_right"]
    with open(path, "w", newline="", encoding="utf-8", errors="replace") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in cols})

def write_findings_jsonl(path: str, rows: Iterable[Dict[str, Any]]):
    with open(path, "w", encoding="utf-8", errors="replace") as fh:
        for r in rows:
            fh.write(json.dumps({
                "record_type":"finding",
                **r
            }, ensure_ascii=False) + "\n")

def dedupe_findings(rows: Iterable[Dict[str, Any]], scope_days: int = 60) -> Iterable[Dict[str, Any]]:
    seen = SeenWindow(days=scope_days)
    for r in rows:
        # prefer URL digest if present, else URL itself
        key = (r.get("rule_id"), r.get("match"), r.get("url"))
        day = r.get("date") or ""
        if seen.keep(day, key):
            yield r

# --- EXIF JSONL ---

def write_exif_jsonl(path: str, rows: Iterable[Dict[str, Any]]):
    with open(path, "w", encoding="utf-8", errors="replace") as fh:
        for r in rows:
            fh.write(json.dumps({
                "record_type":"exif",
                **r
            }, ensure_ascii=False) + "\n")

def dedupe_exif(rows: Iterable[Dict[str, Any]], scope_days: int = 60) -> Iterable[Dict[str, Any]]:
    seen = SeenWindow(days=scope_days)
    for r in rows:
        # use image_url or image_digest if available
        key = (r.get("image_url"), r.get("image_digest"))
        day = r.get("date") or ""
        if seen.keep(day, key):
            yield r

# --- Embedded links ---

def write_embedded_csv(path: str, rows: Iterable[Dict[str, Any]]):
    cols = ["date","source_url","record_type","embed_type","embedded_url","embedded_host","embedded_etld1","kept_reason"]
    with open(path, "w", newline="", encoding="utf-8", errors="replace") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in cols})

def write_embedded_jsonl(path: str, rows: Iterable[Dict[str, Any]]):
    with open(path, "w", encoding="utf-8", errors="replace") as fh:
        for r in rows:
            fh.write(json.dumps({
                "record_type":"embedded_link",
                **r
            }, ensure_ascii=False) + "\n")

def dedupe_embedded(rows: Iterable[Dict[str, Any]], scope_days: int = 60) -> Iterable[Dict[str, Any]]:
    seen = SeenWindow(days=scope_days)
    for r in rows:
        key = (r.get("embedded_etld1"), r.get("embedded_host"), (r.get("embedded_url") or "")[:128], r.get("embed_type"))
        day = r.get("date") or ""
        if seen.keep(day, key):
            yield r
