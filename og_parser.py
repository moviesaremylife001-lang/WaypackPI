# waypack/og_parser.py
from __future__ import annotations
import re
from typing import List

_META_RE = re.compile(
    r'<meta\s+(?:property=["\']og:image["\']|name=["\']twitter:image["\'])\s+content=["\'](?P<u>[^"\'>]+)["\']',
    re.IGNORECASE,
)
_LINK_IMG_RE = re.compile(
    r'<link\s+rel=["\']image_src["\']\s+href=["\'](?P<u>[^"\'>]+)["\']',
    re.IGNORECASE,
)

def extract_og_images(html: str) -> List[str]:
    """Return candidate image URLs from OG/Twitter/link tags (as they appear in HTML)."""
    urls = []
    urls += [m.group("u") for m in _META_RE.finditer(html)]
    urls += [m.group("u") for m in _LINK_IMG_RE.finditer(html)]
    # dedup, keep order
    seen = set()
    out = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out
