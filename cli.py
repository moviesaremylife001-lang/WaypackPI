# waypack/cli.py
from __future__ import annotations

import argparse
import os
import sys
from typing import List, Dict, Any

from .cdx_client import CDXClient
from .embedded import extract_embeds
from .exif_reader import read_jpeg_exif_to_text
from .exporters import (
    write_findings_csv, write_findings_jsonl, dedupe_findings,
    write_exif_jsonl, dedupe_exif,
    write_embedded_csv, write_embedded_jsonl, dedupe_embedded,
    sha256_hex,
)
from .fetcher import Fetcher, FetchResult
from .logger import RunLogger
from .og_parser import extract_og_images
from .progress import Progress
from .scanner import load_rules, scan_text
from .urltools import host, etld1, absolutize

DENYLIST_DEFAULT = {
    "google.com", "googletagmanager.com", "google-analytics.com", "gstatic.com", "googleapis.com", "doubleclick.net",
    "youtube.com", "youtu.be", "facebook.com", "fbcdn.net", "twitter.com", "t.co",
    "cdn.jsdelivr.net", "unpkg.com", "cloudflare.com", "cloudflareinsights.com", "bootstrapcdn.com",
    "fontawesome.com", "fonts.googleapis.com", "fonts.gstatic.com", "gravatar.com", "hotjar.com", "segment.io",
    "mixpanel.com", "analytics.yahoo.com", "bing.com", "akamaihd.net", "adobe.com",
    "image.tmdb.org", "themoviedb.org", "imdb.com", "fanart.tv", "trakt.tv", "letterboxd.com",
    "imgur.com", "flickr.com", "staticflickr.com", "pinterest.com", "googlestatic.com",
}

KEEP_KEYWORDS_DEFAULT = {"video", "player", "embed", "watch", "stream", "hls", "m3u8", "playlist"}


def _fmt_date(yyyymmdd: str) -> str:
    return f"{yyyymmdd[:4]}-{yyyymmdd[4:6]}-{yyyymmdd[6:8]}"


def main(argv=None):
    p = argparse.ArgumentParser("waypack")
    p.add_argument("--domain", required=True)
    p.add_argument("--from", dest="date_from", required=True)
    p.add_argument("--to", dest="date_to", required=True)
    p.add_argument("--status", default="200")
    p.add_argument("--mime", default="text/html")
    p.add_argument("--max-bytes", type=int, default=5_000_000)
    p.add_argument("--timeout", type=int, default=15)
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--rps", type=float, default=2.0)

    p.add_argument("--include", default="aws,github,stripe,webhooks,ga,keys,jwt")
    p.add_argument("--exclude", default="pii")

    p.add_argument("--images", default="og", choices=["og", "off"])
    p.add_argument("--image-types", default="jpeg")
    p.add_argument("--image-per-day", type=int, default=8)
    p.add_argument("--image-min-bytes", type=int, default=30_000)
    p.add_argument("--image-max-bytes", type=int, default=3_000_000)
    p.add_argument("--exif-only", action="store_true", default=True)

    p.add_argument("--embedded", default="on", choices=["on", "off"])
    p.add_argument("--embedded-sameparty", action="store_true", default=False)
    p.add_argument("--embedded-keep-keywords", default=",".join(sorted(KEEP_KEYWORDS_DEFAULT)))
    p.add_argument("--embedded-denylist", default="builtin")

    p.add_argument("--dedupe", default="scope=window")
    p.add_argument("--dedupe-window", type=int, default=60)

    p.add_argument("--csv", default="findings.csv")
    p.add_argument("--json", default="findings.jsonl")
    p.add_argument("--exif-json", default="images_exif.jsonl")
    p.add_argument("--embedded-csv", default="embedded_links.csv")
    p.add_argument("--embedded-json", default="embedded_links.jsonl")
    p.add_argument("--log-file", default="run.log")
    p.add_argument("--no-progress", action="store_true")
    p.add_argument("--save-assets", default="", help="Directory to save raw HTML/JPEG assets (optional)")
    p.add_argument("--mirror-log", action="store_true")

    args = p.parse_args(argv)
    assets_dir = args.save_assets.strip()
    save_html_dir = save_img_dir = ""
    if assets_dir:
        save_html_dir = os.path.join(assets_dir, "html")
        save_img_dir = os.path.join(assets_dir, "img")
        os.makedirs(save_html_dir, exist_ok=True)
        os.makedirs(save_img_dir, exist_ok=True)

    families_include = {s.strip() for s in args.include.split(",") if s.strip()}
    families_exclude = {s.strip() for s in args.exclude.split(",") if s.strip()}
    keep_keywords = {s.strip().lower() for s in
                     args.embedded_keep_keywords.split(",")} if args.embedded != "off" else set()

    # denylist
    if args.embedded_denylist == "builtin":
        denylist = set(DENYLIST_DEFAULT)
    else:
        denylist = set()
        try:
            with open(args.embedded_denylist, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    d = line.strip().lower()
                    if d and not d.startswith("#"):
                        denylist.add(d)
        except Exception:
            denylist = set(DENYLIST_DEFAULT)

    progress = Progress(enabled=not args.no_progress)
    runlog = RunLogger(args.log_file, mirror_stdout=args.mirror_log)

    cdx = CDXClient(rps=args.rps)
    fetch = Fetcher(rps=args.rps, timeout=args.timeout, max_bytes=args.max_bytes, retries=args.retries)
    rules = load_rules("rules")

    records = list(
        cdx.query_daily_sample(args.domain, args.date_from, args.date_to, statuscode=args.status, mimetype=args.mime))
    progress.set_days_total(len(records))

    findings: List[Dict[str, Any]] = []
    exif_rows: List[Dict[str, Any]] = []
    embedded_rows: List[Dict[str, Any]] = []

    tgt_etld1 = etld1(args.domain)
    for rec in records:
        progress.next_day()
        ts = rec["timestamp"]
        day = _fmt_date(ts[:8])
        original = rec["original"]
        page_url = fetch.to_archive_url(ts, original, id_mode=True)

        # Fetch HTML
        runlog.count("HTML_ORIG", 1)
        fr: FetchResult = fetch.get(page_url)
        if not (fr.ok and fr.mime and fr.mime.startswith("text/html")):
            runlog.count("HTML_SKIPPED", 1)
            runlog.log("WARN", "SKIP_HTML", url=page_url, status=fr.status, mime=fr.mime or "", reason=fr.error or "")
            progress.inc_html_skip();
            progress.render()
            continue

        html_bytes = fr.data or b""
        try:
            text = html_bytes.decode("utf-8", errors="replace")
        except Exception:
            text = html_bytes.decode(errors="replace")

        runlog.count("HTML_KEPT", 1)
        runlog.log("INFO", "FETCH_HTML", url=page_url, status=fr.status, mime=fr.mime, bytes=fr.bytes_read)
        # compute digest & optionally save HTML
        html_digest = sha256_hex(html_bytes)
        if assets_dir:
            html_path = os.path.join(save_html_dir, f"{day}_{html_digest}.html")
            try:
                with open(html_path, "wb") as fh:
                    fh.write(html_bytes)
                runlog.log("INFO", "SAVE_HTML", url=page_url, path=html_path)
            except Exception as e:
                runlog.log("WARN", "SAVE_HTML_FAIL", url=page_url, error=str(e))

        progress.inc_html_ok();
        progress.render()

        # Regex findings (HTML)
        for hit in scan_text(text, rules, families_include, families_exclude):
            findings.append({
                "date": day,
                "url": page_url,
                "status": fr.status,
                "mime": fr.mime,
                "bytes": fr.bytes_read,
                "file_digest": html_digest,
                **hit
            })

            runlog.count("FIND_ORIG", 1)
            progress.inc_finds_kept();
            progress.render()

        # Embedded links
        if args.embedded != "off":
            for emb in extract_embeds(text, original, tgt_etld1 or "", denylist, keep_keywords,
                                      sameparty=args.embedded_sameparty):
                embedded_rows.append({
                    "date": day, "source_url": page_url, **emb
                })
                runlog.count("EMB_ORIG", 1)
                progress.inc_embeds_kept();
                progress.render()

        # OG JPEGs (first-party only)
        if args.images == "og" and "jpeg" in args.image_types.lower():
            candidates = extract_og_images(text)
            kept = 0
            for rel in candidates:
                if kept >= args.image_per_day:
                    break
                abs_u = absolutize(original, rel)
                h = host(abs_u) or ""
                t = etld1(h) or ""
                if not h or not t:
                    continue
                if t != (tgt_etld1 or ""):
                    continue

                img_url = fetch.to_archive_url(ts, abs_u, id_mode=True)
                r = fetch.get(img_url)
                runlog.count("IMG_ORIG", 1)
                if not (r.ok and r.mime and r.mime.lower().startswith("image/jpeg")):
                    runlog.count("IMG_SKIPPED", 1)
                    runlog.log("WARN", "SKIP_IMAGE", url=img_url, status=r.status, mime=r.mime or "",
                               reason=r.error or "")
                    progress.inc_imgs_skip();
                    progress.render()
                    continue
                if r.bytes_read < args.image_min_bytes or r.bytes_read > args.image_max_bytes:
                    runlog.count("IMG_SKIPPED", 1)
                    runlog.log("WARN", "SKIP_IMAGE", url=img_url, reason="size_bounds", bytes=r.bytes_read)
                    progress.inc_imgs_skip();
                    progress.render()
                    continue

                ex = read_jpeg_exif_to_text(r.data or b"")
                if not ex:
                    if args.exif_only:
                        runlog.count("IMG_SKIPPED", 1)
                        runlog.log("WARN", "EXIF_EMPTY", url=img_url)
                        progress.inc_imgs_skip();
                        progress.render()
                        continue

                exif_rows.append({
                    "date": day,
                    "src_type": "og",
                    "image_url": img_url,
                    "image_bytes": r.bytes_read,
                    "exif": (ex or {}).get("tags", {}),
                    "gps": (ex or {}).get("gps"),
                    "exif_text": (ex or {}).get("exif_text", ""),
                    "image_digest": sha256_hex(r.data or b""),
                })
                runlog.count("EXIF_ORIG", 1)
                runlog.log("INFO", "EXIF_OK", url=img_url, bytes=r.bytes_read, tags=len((ex or {}).get("tags", {})))
                # save JPEG to disk if requested
                if assets_dir:
                    img_digest = exif_rows[-1]["image_digest"]
                    img_path = os.path.join(save_img_dir, f"{day}_{img_digest}.jpg")
                    try:
                        with open(img_path, "wb") as fh:
                            fh.write(r.data or b"")
                        runlog.log("INFO", "SAVE_IMAGE", url=img_url, path=img_path)
                    except Exception as e:
                        runlog.log("WARN", "SAVE_IMAGE_FAIL", url=img_url, error=str(e))

                progress.inc_imgs_kept();
                progress.render()
                kept += 1

            # Scan EXIF text with OSINT rules
            for er in exif_rows[-kept:] if kept else []:
                txt = er.get("exif_text", "")
                if not txt:
                    continue
                for hit in scan_text(txt, rules, families_include, families_exclude):
                    findings.append({
                        "date": day, "url": er["image_url"], "status": 200, "mime": "image/jpeg",
                        "bytes": er["image_bytes"],
                        "image_digest": er.get("image_digest", ""),
                        **hit
                    })
                    runlog.count("FIND_ORIG", 1)
                    progress.inc_finds_kept();
                    progress.render()

    # DEDUPE + WRITE
    window = args.dedupe_window
    findings_d = list(dedupe_findings(findings, scope_days=window))
    exif_d = list(dedupe_exif(exif_rows, scope_days=window))
    embedded_d = list(dedupe_embedded(embedded_rows, scope_days=window))

    runlog.count("FIND_DEDUPED", max(0, len(findings) - len(findings_d)))
    runlog.count("FIND_KEPT", len(findings_d))
    runlog.count("EXIF_DEDUPED", max(0, len(exif_rows) - len(exif_d)))
    runlog.count("EXIF_KEPT", len(exif_d))
    runlog.count("EMB_DEDUPED", max(0, len(embedded_rows) - len(embedded_d)))
    runlog.count("EMB_KEPT", len(embedded_d))

    write_findings_csv(args.csv, findings_d)
    write_findings_jsonl(args.json, findings_d)
    write_exif_jsonl(args.exif_json, exif_d)
    if args.embedded != "off":
        write_embedded_csv(args.embedded_csv, embedded_d)
        write_embedded_jsonl(args.embedded_json, embedded_d)

    progress.done()
    runlog.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
