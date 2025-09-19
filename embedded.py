# waypack/embedded.py
from __future__ import annotations
import re
from typing import Iterable, Dict, Any, Set
from .urltools import absolutize, host, etld1

# Tags to inspect for src/href
_TAG_RE = re.compile(
    r"<(?P<tag>iframe|embed|video|source|a)\b[^>]*?\s(?P<attr>src|href)\s*=\s*['\"](?P<url>[^'\"<>]+)['\"][^>]*>",
    re.IGNORECASE
)
# Inline absolute URL finder (quick and loose)
_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.IGNORECASE)

def extract_embeds(
    html: str,
    base_original_url: str,
    target_etld1: str,
    denylist: Set[str],
    keep_keywords: Set[str],
    sameparty: bool = False,
) -> Iterable[Dict[str, Any]]:
    seen = set()

    # 1) Tag-based URLs
    for m in _TAG_RE.finditer(html):
        tag = m.group("tag").lower()
        urel = m.group("url")
        url = absolutize(base_original_url, urel)
        h = host(url)
        t = etld1(h) if h else None
        if not h or not t:
            continue
        if t in denylist or h in denylist:
            continue
        third_party = (t != target_etld1)
        if not sameparty and not third_party:
            continue
        kept_reason = "third_party" if third_party else "sameparty"
        if any(k in url.lower() for k in keep_keywords):
            kept_reason = "keyword"
        key = (tag, h, url[:128])
        if key in seen:
            continue
        seen.add(key)
        yield {
            "embed_type": tag if tag != "a" else "link",
            "embedded_url": url,
            "embedded_host": h,
            "embedded_etld1": t,
            "kept_reason": kept_reason,
        }

    # 2) Inline absolute URLs
    for m in _URL_RE.finditer(html):
        url = m.group(0)
        h = host(url)
        t = etld1(h) if h else None
        if not h or not t:
            continue
        if t in denylist or h in denylist:
            continue
        third_party = (t != target_etld1)
        if not sameparty and not third_party:
            continue
        kept_reason = "third_party"
        if any(k in url.lower() for k in keep_keywords):
            kept_reason = "keyword"
        key = ("inline_url", h, url[:128])
        if key in seen:
            continue
        seen.add(key)
        yield {
            "embed_type": "inline_url",
            "embedded_url": url,
            "embedded_host": h,
            "embedded_etld1": t,
            "kept_reason": kept_reason,
        }
