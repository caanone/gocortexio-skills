# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Behavioural tests for ``scripts/lint_rule.py``.

Each fixture under ``tests/fixtures/`` exercises one of the parser-
conformance rules the bundled linter is responsible for. The tests
both import the ``lint()`` function directly and shell out to the CLI
to confirm the exit-code contract.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _helpers import bundle_root  # noqa: E402


FIXTURES = Path(__file__).resolve().parent / "fixtures"
LINT_SCRIPT = bundle_root() / "scripts" / "lint_rule.py"


def _load_lint():
    """Import ``lint()`` from the bundled script without making the
    script a permanent member of any package."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("lint_rule", LINT_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod.lint


lint = _load_lint()


def _rule_ids(fixture_name: str) -> list:
    source = (FIXTURES / fixture_name).read_text(encoding="utf-8")
    return [v["rule_id"] for v in lint(source)]


class TestCleanFixture(unittest.TestCase):
    """A well-formed rule must produce zero violations."""

    def test_no_violations(self):
        ids = _rule_ids("clean_rule.xql")
        self.assertEqual(ids, [], f"expected silence, got {ids}")


class TestSyntacticRules(unittest.TestCase):
    """Each fixture must surface its target rule id."""

    cases = [
        ("err012_infix_arithmetic.xql", "ERR-012"),
        ("err013_compound_null_guard.xql", "ERR-013"),
        ("err014_bareword_boolean.xql", "ERR-014"),
        ("err015_to_number_into_integer_field.xql", "ERR-015"),
        ("err016_invented_path.xql", "ERR-016"),
        ("err017_arraymap_passthrough.xql", "ERR-017"),
        ("err018_missing_cast.xql", "ERR-018"),
        ("err024_sibling_reference.xql", "ERR-024"),
        ("err027_anchor_read.xql", "ERR-027"),
    ]

    def test_each_fixture_fires(self):
        for fixture, expected in self.cases:
            with self.subTest(fixture=fixture, rule=expected):
                ids = _rule_ids(fixture)
                self.assertIn(
                    expected,
                    ids,
                    f"{fixture}: expected {expected} in {ids}",
                )


class TestCliContract(unittest.TestCase):
    """End-to-end: command-line invocation, exit codes, JSON shape."""

    def _run(self, fixture: str, extra: list = ()) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(LINT_SCRIPT), str(FIXTURES / fixture), *extra],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_clean_exit_zero_and_empty_json(self):
        cp = self._run("clean_rule.xql")
        self.assertEqual(cp.returncode, 0, cp.stderr)
        parsed = json.loads(cp.stdout)
        self.assertEqual(parsed, [])

    def test_error_exits_one_and_emits_violation(self):
        cp = self._run("err012_infix_arithmetic.xql")
        self.assertEqual(cp.returncode, 1, cp.stderr)
        parsed = json.loads(cp.stdout)
        self.assertTrue(parsed, "expected at least one violation")
        self.assertEqual(parsed[0]["rule_id"], "ERR-012")
        self.assertEqual(parsed[0]["severity"], "error")
        self.assertIn("line", parsed[0])
        self.assertIn("message", parsed[0])

    def test_missing_file_exits_two(self):
        cp = subprocess.run(
            [sys.executable, str(LINT_SCRIPT), "/nonexistent/rule.xql"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(cp.returncode, 2)

    def test_text_format(self):
        cp = self._run("err012_infix_arithmetic.xql", ["--format", "text"])
        self.assertEqual(cp.returncode, 1)
        self.assertIn("ERR-012", cp.stdout)


class TestErr027Branches(unittest.TestCase):
    """ERR-027 has two detail branches: a self-referential anchor lift
    (`_x = coalesce(_x, ...)`) and a bare read of an underscore field
    never assigned in the rule. Lock both so a future change cannot
    silently collapse one."""

    def _err027(self, source: str) -> list:
        return [v for v in lint(source) if v["rule_id"] == "ERR-027"]

    def test_both_branches_fire(self):
        source = (FIXTURES / "err027_anchor_read.xql").read_text(encoding="utf-8")
        hits = self._err027(source)
        names = {v["line"]: v["message"] for v in hits}
        joined = " ".join(names.values())
        self.assertIn("only ever assigned from its own value", joined)
        self.assertIn("read but never assigned", joined)
        self.assertGreaterEqual(len(hits), 2, f"expected both branches, got {hits}")

    def test_self_sufficient_derivation_is_silent(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            "    _resource_type = json_extract_scalar(_raw_log, \"$.resource_type\"),\n"
            "    _action_class = if(_resource_type != null,\n"
            "        arrayindex(split(_resource_type, \"_\"), 0))\n"
            "| alter\n"
            "    xdm.target.resource.type = _resource_type\n"
            ";\n"
        )
        self.assertEqual(self._err027(source), [])

    def test_reserved_underscores_are_silent(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            "    xdm.event.id = _id,\n"
            "    xdm.event.type = _log_type\n"
            ";\n"
        )
        self.assertEqual(self._err027(source), [])


class TestCascadeHint(unittest.TestCase):
    """INFO-012 fires when two parser-conformance violations land
    within a single source line of each other."""

    def test_info012_fires_on_adjacent_violations(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            "    _x = json_extract_scalar(_raw_log, \"$.x\"),\n"
            "    _y = json_extract_scalar(_raw_log, \"$.y\")\n"
            "| alter\n"
            "    xdm.event.duration = _x - _y,\n"
            "    xdm.target.port = to_number(_y)\n"
            ";\n"
        )
        ids = [v["rule_id"] for v in lint(source)]
        self.assertIn("ERR-012", ids)
        self.assertIn("ERR-015", ids)
        self.assertIn("INFO-012", ids)


if __name__ == "__main__":
    unittest.main()
