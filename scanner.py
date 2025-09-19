# waypack/scanner.py
from __future__ import annotations
import json, re, os
from dataclasses import dataclass
from typing import List, Iterable, Dict, Any, Optional

@dataclass
class Rule:
    rule_id: str
    family: str
    pattern: str
    flags: int = re.IGNORECASE
    min_len: int = 0
    entropy_min: float = 0.0
    source: str = "local"

CTX = 48  # context window chars either side

# Fallback minimal ruleset so the tool runs before you vendor full packs
_FALLBACK_RULES = [
    Rule("stripe.secret_key", "payments", r"\bsk_(live|test)_[0-9a-zA-Z]{16,}\b", re.IGNORECASE),
    Rule("github.pat", "developer", r"\bghp_[0-9a-zA-Z]{36,}\b", re.IGNORECASE),
    Rule("aws.access_key", "cloud", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", 0),
    Rule("slack.webhook", "webhooks", r"https://hooks\.slack\.com/services/[A-Z0-9]{9,}/[A-Z0-9]{9,}/[A-Za-z0-9]{24,}", re.IGNORECASE),
    Rule("discord.webhook", "webhooks", r"https://discord(?:app)?\.com/api/webhooks/[0-9]{16,}/[A-Za-z0-9._-]{30,}", re.IGNORECASE),
    Rule("ga.measurement_id", "analytics", r"\bG-[A-Z0-9]{8,}\b", 0),
    Rule("gtm.container", "analytics", r"\bGTM-[A-Z0-9]{5,}\b", 0),
    Rule("private_key.block", "keys", r"-----BEGIN (?:RSA|DSA|EC) PRIVATE KEY-----", 0),
    Rule("jwt.like", "keys", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", 0),
    Rule("google.maps.key", "api", r"\bAIza[0-9A-Za-z\-_]{30,}\b", 0),
]

def _load_json_rules(path: str) -> List[Rule]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    out: List[Rule] = []
    for obj in data:
        try:
            out.append(
                Rule(
                    rule_id=obj["rule_id"],
                    family=obj.get("family","misc"),
                    pattern=obj["pattern"],
                    flags=re.IGNORECASE if obj.get("ignorecase", True) else 0,
                    min_len=int(obj.get("min_len", 0)),
                    entropy_min=float(obj.get("entropy_min", 0.0)),
                    source=obj.get("source", "merged"),
                )
            )
        except Exception:
            continue
    return out

def load_rules(rules_dir: str = "rules") -> List[Rule]:
    """
    Load vendored rules. If rules/merged_rules.json exists, use it; else fallback.
    merged_rules.json format: list of {rule_id,family,pattern,ignorecase?,min_len?,entropy_min?,source?}
    """
    merged = os.path.join(rules_dir, "merged_rules.json")
    if os.path.isfile(merged):
        rules = _load_json_rules(merged)
        if rules:
            return rules
    return _FALLBACK_RULES[:]  # copy

def scan_text(text: str, rules: List[Rule], families_include: Optional[set[str]] = None, families_exclude: Optional[set[str]] = None) -> Iterable[Dict[str, Any]]:
    if not text:
        return
    inc = families_include
    exc = families_exclude
    for r in rules:
        if inc and r.family not in inc:
            continue
        if exc and r.family in exc:
            continue
        try:
            for m in re.finditer(r.pattern, text, r.flags):
                s, e = m.start(), m.end()
                match = m.group(0)
                if r.min_len and len(match) < r.min_len:
                    continue
                # (Optional) entropy gate could be added here
                ctx_left = text[max(0, s-CTX):s]
                ctx_right = text[e:e+CTX]
                yield {
                    "rule_id": r.rule_id,
                    "family": r.family,
                    "match": match,
                    "ctx_left": ctx_left,
                    "ctx_right": ctx_right,
                    "source": r.source,
                }
        except re.error:
            continue
