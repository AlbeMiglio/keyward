#!/usr/bin/env python3
"""Sanitized output must be a fixed point of detect() — else the block+paste
hook re-fires on its own output and loops. stdlib-only (unittest)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from detect import detect  # noqa: E402

# Synthetic keys, split so no contiguous key-shaped literal lands in the repo
# (GitHub push protection flags it). They cannot be written as EXAMPLE/FAKE
# either — the placeholder filter would skip them and the test would pass vacuously.
_SB_SECRET = "sb_" + "secret_nR7auGThKosTVDgi9A0nTA_1q5WcKH9"
_SB_PUBLISHABLE = "sb_" + "publishable_Md4S8bgD8bmSsUq7olbaLA_VdP7WEz4"


def sanitize(prompt, secrets):
    for s in sorted(secrets, key=lambda x: x["span"][0], reverse=True):
        a, b = s["span"]
        ref = f"<<secret:{s['name']} stored at ~/.claude/secrets/{s['name']}.txt>>"
        prompt = prompt[:a] + ref + prompt[b:]
    return prompt


class TestIdempotent(unittest.TestCase):
    # Each prompt must be detected once, then its sanitized form must detect nothing.
    CASES = [
        "/keyward:key claude=sk-ant-oat01-AAAABBBBCCCCDDDDEEEE",  # explicit_slash
        "use KEY=Xy3z9abQpieJ now",                               # explicit_default
        "set api2_token=Xy3z9abQ to deploy",                      # context w/ digit in name
        "deploy with ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIII",   # regex
        _SB_SECRET,                                               # supabase secret
        _SB_PUBLISHABLE,                                          # supabase publishable
    ]

    def test_sanitized_is_fixed_point(self):
        for p in self.CASES:
            first = detect(p)["secrets"]
            self.assertTrue(first, f"expected a detection for: {p}")
            p2 = sanitize(p, first)
            self.assertEqual(detect(p2)["secrets"], [], f"re-detected (would loop): {p2}")


if __name__ == "__main__":
    unittest.main()
