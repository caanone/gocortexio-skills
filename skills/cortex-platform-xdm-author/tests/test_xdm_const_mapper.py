# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for ``scripts/xdm_const_mapper.py``.

Pins the two contracts that matter: the categorical mapper resolves a
field's XDM_CONST group, token-matches observed values to real members,
and NEVER invents a constant for an unmatched value; the banded mode
emits the paired severity / log-level chains. Generated snippets must
embed into a lint-clean rule.
"""

from __future__ import annotations

import importlib.util
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


_mapper = _load("xdm_const_mapper")
_lint = _load("lint_rule")


def _embed(snippet: str) -> str:
    # Drop trailing // comment lines so the snippet sits inside the rule.
    body = "\n".join(
        ln for ln in snippet.splitlines() if not ln.strip().startswith("//")
    )
    return (
        "[MODEL: dataset=acme_demo_raw]\n"
        "filter\n"
        "    _raw_log != null\n"
        "| alter\n"
        '    _value = json_extract_scalar(_raw_log, "$.v")\n'
        "| alter\n"
        '    xdm.observer.vendor = "Acme",\n'
        '    xdm.event.type = "ALERT",\n'
        f"    {body}\n"
        ";\n"
    )


class TestCategorical(unittest.TestCase):
    def test_outcome_mapping(self):
        snippet, unmapped = _mapper.map_categorical(
            "xdm.event.outcome", ["success", "failure", "partial"], "_outcome"
        )
        self.assertIn("XDM_CONST.OUTCOME_SUCCESS", snippet)
        self.assertIn("XDM_CONST.OUTCOME_FAILED", snippet)   # failure -> failed (stem)
        self.assertIn("XDM_CONST.OUTCOME_PARTIAL", snippet)
        self.assertEqual(unmapped, [])

    def test_never_invents_constant(self):
        snippet, unmapped = _mapper.map_categorical(
            "xdm.event.outcome", ["success", "frobnicated"], "_o"
        )
        self.assertIn("frobnicated", unmapped)
        self.assertNotIn("FROBNICATED", snippet)
        self.assertNotIn("XDM_CONST.OUTCOME_FROBNICATED", snippet)

    def test_http_method_exact(self):
        snippet, _ = _mapper.map_categorical(
            "xdm.network.http.method", ["GET", "POST"], "_m"
        )
        self.assertIn("XDM_CONST.HTTP_METHOD_GET", snippet)
        self.assertIn("XDM_CONST.HTTP_METHOD_POST", snippet)

    def test_non_const_field_raises(self):
        with self.assertRaises(ValueError):
            _mapper.map_categorical("xdm.source.ipv4", ["x"], "_t")

    def test_unknown_field_raises(self):
        with self.assertRaises(ValueError):
            _mapper.map_categorical("xdm.not.real", ["x"], "_t")

    def test_all_unmapped_raises(self):
        with self.assertRaises(ValueError):
            _mapper.map_categorical("xdm.event.outcome", ["zzz", "qqq"], "_t")

    def test_snippet_embeds_lint_clean(self):
        snippet, _ = _mapper.map_categorical(
            "xdm.event.outcome", ["success", "failure"], "_value"
        )
        rule = _embed(snippet)
        errors = [v for v in _lint.lint(rule) if v["severity"] == "error"]
        self.assertEqual(errors, [], f"{errors}\n{rule}")


class TestBanded(unittest.TestCase):
    def test_banded_pairs(self):
        out = _mapper.banded("_score", [80, 50, 30])
        self.assertIn("xdm.alert.severity = if(", out)
        self.assertIn("xdm.event.log_level = if(", out)
        self.assertIn('_score >= 80, "Critical"', out)
        self.assertIn("XDM_CONST.LOG_LEVEL_CRITICAL", out)
        self.assertIn('_score != null, "Low"', out)

    def test_banded_embeds_lint_clean(self):
        out = _mapper.banded("_value", [80, 50, 30])
        rule = _embed(out)
        errors = [v for v in _lint.lint(rule) if v["severity"] == "error"]
        self.assertEqual(errors, [], f"{errors}\n{rule}")

    def test_bad_thresholds(self):
        with self.assertRaises(ValueError):
            _mapper.banded("_s", [80, 50])


class TestCli(unittest.TestCase):
    def _run(self, *args, **kw):
        return subprocess.run(
            [sys.executable, str(SCRIPTS / "xdm_const_mapper.py"), *args],
            capture_output=True, text=True, check=False,
        )

    def test_cli_categorical(self):
        cp = self._run(
            "--field", "xdm.event.outcome", "--values", "success,failure",
            "--temp", "_o",
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("XDM_CONST.OUTCOME_SUCCESS", cp.stdout)

    def test_cli_banded(self):
        cp = self._run("--banded", "--temp", "_score")
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("XDM_CONST.LOG_LEVEL_CRITICAL", cp.stdout)

    def test_cli_missing_args(self):
        cp = self._run("--field", "xdm.event.outcome")
        self.assertEqual(cp.returncode, 1)


if __name__ == "__main__":
    unittest.main()
