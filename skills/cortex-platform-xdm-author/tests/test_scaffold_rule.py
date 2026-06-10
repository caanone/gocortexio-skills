# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for ``scripts/scaffold_rule.py``.

The scaffolder turns a profile_log.py worksheet into a starter MODEL
rule. The contract these tests pin: the output always lints clean (the
self-gate), is deterministic, wires the high-confidence scalar anchors
into the drain stage with type-correct wrapping, never duplicates a
target, and routes array / XDM_CONST leaves to the header TODO block
instead of emitting a broken assignment.
"""

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
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


_scaffold = _load("scaffold_rule")
_profile = _load("profile_log")
_lint = _load("lint_rule")


def _worksheet(fixture: str) -> dict:
    text = (FIXTURES / fixture).read_text(encoding="utf-8")
    return _profile.profile(str(FIXTURES / fixture), text)


def _make(fixture: str, **kw) -> str:
    ws = _worksheet(fixture)
    return _scaffold.scaffold(
        ws,
        kw.get("vendor", "Acme"),
        kw.get("product", "Demo"),
        kw.get("dataset", "acme_demo_raw"),
        kw.get("min_frequency", 3),
    )


class TestScaffoldOutput(unittest.TestCase):
    def test_kv_scaffold_lints_clean(self):
        rule = _make("sample.kv")
        errors = [v for v in _lint.lint(rule) if v["severity"] == "error"]
        self.assertEqual(errors, [], f"scaffold should self-gate clean: {errors}")

    def test_json_scaffold_lints_clean(self):
        rule = _make("acmeshield_waf.log", vendor="AcmeShield", product="WAF")
        errors = [v for v in _lint.lint(rule) if v["severity"] == "error"]
        self.assertEqual(errors, [], f"scaffold should self-gate clean: {errors}")

    def test_deterministic(self):
        a = _make("sample.kv")
        b = _make("sample.kv")
        self.assertEqual(a, b)

    def test_has_model_header_and_terminator(self):
        rule = _make("sample.kv")
        self.assertIn("[MODEL: dataset=acme_demo_raw]", rule)
        self.assertTrue(rule.rstrip().endswith(";"))
        self.assertIn("xdm.observer.vendor = \"Acme\"", rule)
        self.assertIn("xdm.observer.product = \"Demo\"", rule)

    def test_high_confidence_anchor_wired(self):
        rule = _make("sample.kv")
        # src_ip is a strong anchor for xdm.source.ipv4.
        self.assertIn("xdm.source.ipv4 = _src_ip", rule)

    def test_integer_field_wrapped(self):
        rule = _make("sample.kv")
        # spt -> xdm.source.port (Number) must be wrapped to_integer(to_number()).
        self.assertIn("xdm.source.port = to_integer(to_number(_spt))", rule)

    def test_no_duplicate_target(self):
        rule = _make("acmeshield_waf.log", vendor="AcmeShield", product="WAF")
        # Only the hardcoded xdm.event.type assignment should appear.
        assign_lines = [
            ln for ln in rule.splitlines()
            if ln.strip().startswith("xdm.event.type =")
        ]
        self.assertEqual(len(assign_lines), 1, assign_lines)

    def test_array_leaves_routed_to_todo(self):
        rule = _make("acmeshield_waf.log", vendor="AcmeShield", product="WAF")
        # transactions[].* leaves must not be extracted; they belong in the
        # TODO block, not the alter stages.
        self.assertNotIn("transactions[].http.method =", rule)
        self.assertIn("Pattern D'", rule)

    def test_array_xdm_field_uses_arraycreate(self):
        # A leaf whose top anchor is an Array-type XDM field must be wrapped.
        ws = {
            "detected_format": "json",
            "record_count": 1,
            "fields": [
                {
                    "path": "mac",
                    "leaf": "mac",
                    "type": "string",
                    "xdm_candidates": [
                        {"xdm_path": "xdm.source.host.mac_addresses",
                         "frequency": 50, "score": 100}
                    ],
                }
            ],
            "object_arrays": [],
        }
        rule = _scaffold.scaffold(ws, "Acme", "Demo", "acme_demo_raw")
        self.assertIn(
            "xdm.source.host.mac_addresses = if(_mac != null, "
            "arraycreate(_mac), null)",
            rule,
        )
        errors = [v for v in _lint.lint(rule) if v["severity"] == "error"]
        self.assertEqual(errors, [])


class TestScaffoldCli(unittest.TestCase):
    def test_stdin_pipe_exit_zero(self):
        ws = json.dumps(_worksheet("sample.kv"))
        cp = subprocess.run(
            [sys.executable, str(SCRIPTS / "scaffold_rule.py"), "-",
             "--vendor", "Acme", "--product", "Demo"],
            input=ws, capture_output=True, text=True, check=False,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("[MODEL: dataset=acme_demo_raw]", cp.stdout)

    def test_bad_json_exits_two(self):
        cp = subprocess.run(
            [sys.executable, str(SCRIPTS / "scaffold_rule.py"), "-"],
            input="not json", capture_output=True, text=True, check=False,
        )
        self.assertEqual(cp.returncode, 2)


if __name__ == "__main__":
    unittest.main()
