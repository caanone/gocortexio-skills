# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the lookup_anchor.py forward / reverse / related modes and
the shared helpers that back them."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from _helpers import bundle_root  # noqa: E402

SCRIPTS = bundle_root() / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


_ai = _load("_anchor_index")


class TestHelpers(unittest.TestCase):
    def test_forward_synonyms_ranked(self):
        data = _ai.load_anchors()
        syns = _ai.forward_synonyms(data, "xdm.source.ipv4")
        self.assertTrue(syns)
        counts = [s["count"] for s in syns]
        self.assertEqual(counts, sorted(counts, reverse=True))
        names = [s["synonym"] for s in syns]
        self.assertIn("src", names)

    def test_forward_synonyms_unknown_path(self):
        data = _ai.load_anchors()
        self.assertEqual(_ai.forward_synonyms(data, "xdm.not.real"), [])

    def test_snake_case_mfa_method_resolves(self):
        # Regression: a snake_case mfa_method must resolve to the real
        # xdm.auth.mfa.method anchor, not return zero (which previously led
        # an agent to bury the value in the description). camelCase and the
        # mfa_type variant must resolve too.
        data = _ai.load_anchors()
        reverse = _ai.build_reverse_index(data)
        for query in ("mfa_method", "mfaMethod", "mfa_type"):
            key = _ai.normalise_synonym(query)
            cands = reverse.get(key, [])
            self.assertTrue(cands, f"{query!r} resolved to nothing")
            self.assertEqual(cands[0]["xdm_path"], "xdm.auth.mfa.method", query)

    def test_related_is_symmetric_and_excludes_self(self):
        rel = _ai.related_fields("xdm.source.ipv4")
        self.assertIn("xdm.target.ipv4", rel)
        self.assertNotIn("xdm.source.ipv4", rel)
        # Symmetry: the partner lists us back.
        self.assertIn("xdm.source.ipv4", _ai.related_fields("xdm.target.ipv4"))

    def test_related_unknown_path_empty(self):
        self.assertEqual(_ai.related_fields("xdm.not.real"), [])


class TestCli(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPTS / "lookup_anchor.py"), *args],
            capture_output=True, text=True, check=False,
        )

    def test_forward_backcompat(self):
        cp = self._run("src_ip")
        self.assertEqual(cp.returncode, 0, cp.stderr)
        data = json.loads(cp.stdout)
        self.assertEqual(data[0]["candidates"][0]["xdm_path"], "xdm.source.ipv4")

    def test_reverse(self):
        cp = self._run("--reverse", "xdm.source.ipv4")
        self.assertEqual(cp.returncode, 0, cp.stderr)
        data = json.loads(cp.stdout)
        self.assertEqual(data["xdm_path"], "xdm.source.ipv4")
        self.assertIn("src", [s["synonym"] for s in data["synonyms"]])

    def test_related(self):
        cp = self._run("--related", "xdm.source.user.username")
        self.assertEqual(cp.returncode, 0, cp.stderr)
        data = json.loads(cp.stdout)
        self.assertIn("xdm.source.user.upn", data["related"])

    def test_bare_usage_exits_one(self):
        cp = self._run()
        self.assertEqual(cp.returncode, 1)


if __name__ == "__main__":
    unittest.main()
