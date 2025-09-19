# waypack/progress.py
from __future__ import annotations
import sys
from dataclasses import dataclass

@dataclass
class Counters:
    days_total: int = 0
    day_idx: int = 0
    html_ok: int = 0
    html_skip: int = 0
    imgs_kept: int = 0
    imgs_skip: int = 0
    embeds_kept: int = 0
    finds_kept: int = 0

class Progress:
    """
    Minimal single-line progress. Call .render() after you bump counters.
    Prints: [day 12/365] html ok: 12 | imgs: 33 kept / 4 skip | embeds: 18 | findings: 27
    """
    def __init__(self, enabled: bool = True, stream = sys.stderr):
        self.enabled = enabled
        self.stream = stream
        self.c = Counters()

    def set_days_total(self, n: int):
        self.c.days_total = max(0, n)

    def next_day(self):
        self.c.day_idx += 1

    def inc_html_ok(self, n: int = 1): self.c.html_ok += n
    def inc_html_skip(self, n: int = 1): self.c.html_skip += n
    def inc_imgs_kept(self, n: int = 1): self.c.imgs_kept += n
    def inc_imgs_skip(self, n: int = 1): self.c.imgs_skip += n
    def inc_embeds_kept(self, n: int = 1): self.c.embeds_kept += n
    def inc_finds_kept(self, n: int = 1): self.c.finds_kept += n

    def render(self):
        if not self.enabled:
            return
        msg = (
            f"[day {self.c.day_idx}/{self.c.days_total}] "
            f"html ok: {self.c.html_ok} "
            f"| imgs: {self.c.imgs_kept} kept / {self.c.imgs_skip} skip "
            f"| embeds: {self.c.embeds_kept} "
            f"| findings: {self.c.finds_kept}"
        )
        # single-line live update
        self.stream.write("\r" + msg + " " * 8)
        self.stream.flush()

    def done(self):
        if not self.enabled:
            return
        # finish with a newline so shell prompt is clean
        self.stream.write("\n")
        self.stream.flush()
