# waypack/urltools.py
from urllib.parse import urlparse, urljoin

# Minimal eTLD+1 resolver:
# - Works for most TLDs by defaulting to last 2 labels.
# - Handles common "second-level" ccTLDs like co.uk, com.au, etc.
# You can extend PSL_SUFFIX_2L if you hit edge cases.
_PSL_SUFFIX_2L = {
    ("ac", "uk"), ("co", "uk"), ("gov", "uk"), ("ltd", "uk"), ("plc", "uk"), ("sch", "uk"),
    ("com", "au"), ("net", "au"), ("org", "au"), ("edu", "au"), ("gov", "au"),
    ("com", "br"), ("net", "br"), ("gov", "br"), ("com", "mx"), ("com", "ar"),
    ("co", "jp"), ("ne", "jp"), ("or", "jp"), ("go", "jp"), ("ac", "jp"),
    ("co", "za"), ("gov", "za"), ("ac", "za"),
}

def parse(url: str):
    """Return urllib.parse.ParseResult (no strict validation)."""
    return urlparse(url)

def absolutize(base_url: str, maybe_relative: str) -> str:
    """Resolve relative URLs against a base (works with Wayback absolute bases too)."""
    try:
        return urljoin(base_url, maybe_relative)
    except Exception:
        return maybe_relative

def host(url: str) -> str | None:
    try:
        h = urlparse(url).hostname
        return h.lower() if h else None
    except Exception:
        return None

def etld1(hostname: str) -> str | None:
    """
    Best-effort eTLD+1:
    - If hostname like sub.example.com -> example.com
    - If hostname like foo.example.co.uk -> example.co.uk
    """
    if not hostname:
        return None
    parts = hostname.lower().split(".")
    if len(parts) < 2:
        return hostname
    # Check known 2-level public suffixes (co.uk, com.au, etc.)
    if len(parts) >= 3 and (parts[-2], parts[-1]) in _PSL_SUFFIX_2L:
        return ".".join(parts[-3:])
    # Default: last two labels
    return ".".join(parts[-2:])
