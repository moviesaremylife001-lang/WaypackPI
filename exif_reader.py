# waypack/exif_reader.py
from __future__ import annotations
from typing import Dict, Any, Optional

# Pillow is optional; we fail soft if it's not installed
try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
except Exception:  # pragma: no cover
    Image = None
    TAGS = {}
    GPSTAGS = {}

def _extract_exif_dict(img) -> Dict[str, Any]:
    exif = getattr(img, "_getexif", lambda: None)()
    if not exif:
        return {}
    out = {}
    for tag_id, value in exif.items():
        name = TAGS.get(tag_id, str(tag_id))
        out[name] = value
    # flatten GPS info if present
    if "GPSInfo" in out and isinstance(out["GPSInfo"], dict):
        gps = {}
        for k, v in out["GPSInfo"].items():
            keyname = GPSTAGS.get(k, str(k))
            gps[keyname] = v
        out["GPSInfo"] = gps
    return out

def _to_decimal(coord, ref) -> Optional[float]:
    # Convert GPS coordinates (deg, min, sec) to decimal degrees
    try:
        d, m, s = coord
        val = float(d[0]) / d[1] + float(m[0]) / m[1] / 60.0 + float(s[0]) / s[1] / 3600.0
        if ref in ("S", "W"):
            val = -val
        return val
    except Exception:
        return None

KEEP_TAGS = {
    "DateTimeOriginal", "Make", "Model", "Orientation", "Software", "Artist",
    "Copyright", "ImageUniqueID", "XResolution", "YResolution",
}

def read_jpeg_exif_to_text(jpeg_bytes: bytes) -> Optional[Dict[str, Any]]:
    """
    Return a dict with 'exif_text' (flat key:value lines), 'tags' (kept fields),
    and 'gps' (lat/lon) if EXIF present; None if no EXIF or Pillow missing.
    """
    if Image is None:
        return None
    try:
        from io import BytesIO
        img = Image.open(BytesIO(jpeg_bytes))
        if img.format != "JPEG":
            return None
        exif = _extract_exif_dict(img)
        if not exif:
            return None

        # pick kept tags
        kept = {k: exif.get(k) for k in KEEP_TAGS if k in exif}
        # GPS
        lat = lon = None
        gps = exif.get("GPSInfo")
        if gps:
            lat = _to_decimal(gps.get("GPSLatitude"), gps.get("GPSLatitudeRef"))
            lon = _to_decimal(gps.get("GPSLongitude"), gps.get("GPSLongitudeRef"))

        # build text blob for regex/URL scanning
        lines = []
        for k, v in kept.items():
            try:
                lines.append(f"{k}: {v}")
            except Exception:
                pass
        if lat is not None and lon is not None:
            lines.append(f"GPSLatitude: {lat}")
            lines.append(f"GPSLongitude: {lon}")
        exif_text = "\n".join(lines)

        return {
            "exif_text": exif_text,
            "tags": kept,
            "gps": {"lat": lat, "lon": lon} if lat is not None and lon is not None else None,
        }
    except Exception:
        return None
