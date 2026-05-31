# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Spot-check the field-anchor synonym index.

Loads assets/field_anchors.json and asserts that a small allowlist of
well-known vendor synonyms resolve to the expected xdm.* target as the
TOP-RANKED candidate. The frozen expectations were sampled from the
shipped JSON; a test failure means either:

  (a) the JSON has been regenerated and the index has shifted under us
      -- update the expectations after confirming the new top candidate
      is actually correct; or
  (b) the JSON has been corrupted -- investigate before updating.

Also asserts:
  - the JSON parses and the top-level shape is what lookup_anchor.py
    expects (schema_version + anchors map);
  - a gibberish synonym returns zero candidates.

The ``normalise_synonym`` function below mirrors the one in
``scripts/lookup_anchor.py`` byte-for-byte; the test does not shell
out to Node.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

# Make ``_helpers`` importable whether unittest was launched via
# ``-m unittest discover -s tests`` (which already puts tests/ on
# sys.path) or via the explicit module form ``-m unittest
# tests.test_field_anchors`` (which does not).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _helpers import read_json  # noqa: E402


def normalise_synonym(raw: str) -> str:
    """Port of normaliseSynonym() from scripts/lookup_anchor.py.

    Steps:
      1. trim + lowercase
      2. strip a leading '@' (JSON-path artefact)
      3. replace runs of '.', '-', whitespace with '_'
      4. strip leading underscores
      5. strip a single 'tmp_' prefix
      6. collapse runs of underscores, strip trailing underscores
    """
    s = (raw or "").strip().lower()
    if s.startswith("@"):
        s = s[1:]
    s = re.sub(r"[.\s-]+", "_", s)
    s = re.sub(r"^_+", "", s)
    if s.startswith("tmp_"):
        s = s[4:]
    s = re.sub(r"_+", "_", s).rstrip("_")
    return s


def build_reverse_index(anchors: dict) -> dict:
    """Build normalised-synonym -> ranked-candidates index."""
    reverse: dict[str, list] = {}
    for xdm_path, entry in anchors.items():
        for syn in entry.get("synonyms", []):
            key = normalise_synonym(syn["synonym"])
            if not key:
                continue
            reverse.setdefault(key, []).append(
                {
                    "xdm_path": xdm_path,
                    "score": syn["count"] * entry["frequency"],
                    "synonym_count": syn["count"],
                    "frequency": entry["frequency"],
                }
            )
    for cands in reverse.values():
        cands.sort(key=lambda c: -c["score"])
    return reverse


# Frozen expectations: (synonym_as_user_might_type_it -> expected_top_xdm_path).
# Each entry was confirmed by inspecting the shipped JSON at bundle time.
# If the index is regenerated and these shift, update with care -- the
# point of the test is to flag drift.
EXPECTED_TOP_CANDIDATES = {
    "src": "xdm.source.ipv4",
    "dst": "xdm.target.ipv4",
    "dpt": "xdm.target.port",
    "spt": "xdm.source.port",
    "username": "xdm.source.user.username",
    "useragent": "xdm.source.user_agent",
    "hostname": "xdm.source.host.hostname",
    "src_port": "xdm.source.port",
    "src_ip": "xdm.source.ipv4",
    "user_agent": "xdm.source.user_agent",
    "destinationip": "xdm.target.ipv4",
    "sourceport": "xdm.source.port",
    # Exercises the normalisation pipeline: dot and case both stripped.
    "Src.IP": "xdm.source.ipv4",
}

GIBBERISH = "__no_such_field_zzz__"


class TestFieldAnchorsShape(unittest.TestCase):
    """Top-level shape of field_anchors.json."""

    def setUp(self):
        self.j = read_json("assets/field_anchors.json")

    def test_top_level_keys_present(self):
        for k in ("schema_version", "anchors"):
            self.assertIn(k, self.j, f"missing top-level key: {k}")

    def test_anchors_map_nonempty(self):
        self.assertIsInstance(self.j["anchors"], dict)
        self.assertGreater(
            len(self.j["anchors"]),
            100,
            f"anchors map suspiciously small: {len(self.j['anchors'])} entries",
        )

    def test_each_anchor_has_frequency_and_synonyms(self):
        # Sample 20 anchors -- a structural defect would manifest on every
        # entry, so a small sample is sufficient.
        sample = list(self.j["anchors"].items())[:20]
        for xdm_path, entry in sample:
            self.assertIsInstance(
                entry.get("frequency"),
                int,
                f"{xdm_path}: frequency is not int",
            )
            self.assertIsInstance(
                entry.get("synonyms"),
                list,
                f"{xdm_path}: synonyms is not list",
            )


class TestSynonymLookups(unittest.TestCase):
    """Frozen expectations for top-1 synonym -> xdm path lookups."""

    @classmethod
    def setUpClass(cls):
        j = read_json("assets/field_anchors.json")
        cls.reverse = build_reverse_index(j["anchors"])

    def test_top_candidate_matches_expectation(self):
        for synonym, expected_top in EXPECTED_TOP_CANDIDATES.items():
            with self.subTest(synonym=synonym):
                key = normalise_synonym(synonym)
                cands = self.reverse.get(key, [])
                self.assertTrue(
                    cands,
                    f"expected at least one candidate for '{synonym}' "
                    f"(normalised: '{key}'); got none",
                )
                self.assertEqual(
                    cands[0]["xdm_path"],
                    expected_top,
                    f"top candidate for '{synonym}' drifted: expected "
                    f"{expected_top}, got {cands[0]['xdm_path']}",
                )

    def test_gibberish_returns_no_candidates(self):
        key = normalise_synonym(GIBBERISH)
        cands = self.reverse.get(key, [])
        self.assertEqual(
            cands,
            [],
            f"gibberish synonym '{GIBBERISH}' unexpectedly matched: {cands}",
        )


class TestNormalisation(unittest.TestCase):
    """Direct exercise of the synonym normaliser."""

    def test_lowercase_and_trim(self):
        self.assertEqual(normalise_synonym("  SRC_IP  "), "src_ip")

    def test_strip_leading_at(self):
        self.assertEqual(normalise_synonym("@severity"), "severity")

    def test_collapse_dots_dashes_spaces(self):
        self.assertEqual(normalise_synonym("Src.IP"), "src_ip")
        self.assertEqual(normalise_synonym("src-ip"), "src_ip")
        self.assertEqual(normalise_synonym("src ip"), "src_ip")

    def test_strip_leading_underscore_and_tmp_prefix(self):
        self.assertEqual(normalise_synonym("_src_ip"), "src_ip")
        self.assertEqual(normalise_synonym("_tmp_src_ip"), "src_ip")
        self.assertEqual(normalise_synonym("tmp_src_ip"), "src_ip")

    def test_collapse_repeated_underscores(self):
        self.assertEqual(normalise_synonym("src__ip__"), "src_ip")


if __name__ == "__main__":
    unittest.main()
