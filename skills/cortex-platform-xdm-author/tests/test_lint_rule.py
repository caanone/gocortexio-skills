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
        ("err019_unused_temp.xql", "ERR-019"),
        ("err020_invented_target.xql", "ERR-020"),
        ("err024_sibling_reference.xql", "ERR-024"),
        ("err025_concat_hidden.xql", "ERR-025"),
        ("err027_anchor_read.xql", "ERR-027"),
        ("warn014_quoted_const.xql", "WARN-014"),
        ("warn035_scalar_into_array.xql", "WARN-035"),
        ("warn037_loglevel_severity.xql", "WARN-037"),
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


class TestStructuralRules(unittest.TestCase):
    """The cheap structural checks (terminal semicolon, trailing comma,
    self-reference, quoted dataset, leading pipe, _time in MODEL) fire on
    minimal inline sources."""

    def _ids(self, source: str) -> list:
        return [v["rule_id"] for v in lint(source)]

    def test_err009_missing_semicolon(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "alter\n"
            '    _x = json_extract_scalar(_raw_log, "$.x")\n'
            "| alter\n"
            "    xdm.event.id = _x\n"
        )
        self.assertIn("ERR-009", self._ids(source))

    def test_err010_trailing_comma(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "alter\n"
            '    _x = json_extract_scalar(_raw_log, "$.x")\n'
            "| alter\n"
            "    xdm.event.id = _x,\n"
            ";\n"
        )
        self.assertIn("ERR-010", self._ids(source))

    def test_err011_self_reference(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "alter\n"
            '    _x = json_extract_scalar(_raw_log, "$.x")\n'
            "| alter\n"
            "    xdm.target.ipv4 = coalesce(xdm.target.ipv4, _x)\n"
            ";\n"
        )
        self.assertIn("ERR-011", self._ids(source))

    def test_warn015_quoted_dataset(self):
        source = (
            '[MODEL: dataset="demo_raw"]\n'
            "alter\n"
            '    _x = json_extract_scalar(_raw_log, "$.x")\n'
            "| alter\n"
            "    xdm.event.id = _x\n"
            ";\n"
        )
        self.assertIn("WARN-015", self._ids(source))

    def test_warn017_leading_pipe(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "| alter\n"
            '    _x = json_extract_scalar(_raw_log, "$.x")\n'
            "| alter\n"
            "    xdm.event.id = _x\n"
            ";\n"
        )
        self.assertIn("WARN-017", self._ids(source))

    def test_warn018_time_in_model(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "alter\n"
            '    _time = parse_epoch(json_extract_scalar(_raw_log, "$.ts"), "MILLIS")\n'
            "| alter\n"
            "    xdm.event.type = \"ALERT\"\n"
            ";\n"
        )
        self.assertIn("WARN-018", self._ids(source))


class TestGcRawGating(unittest.TestCase):
    """ERR-019 (unused temp) and ERR-025 (concat-hidden temp) are a hard
    block only on _gc_raw datasets. On a plain _raw dataset the same
    shapes are tolerated by the live tenant, so the linter stays silent."""

    def _ids(self, source: str) -> list:
        return [v["rule_id"] for v in lint(source)]

    def test_err019_silent_on_plain_raw(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "alter\n"
            '    _used = json_extract_scalar(_raw_log, "$.id"),\n'
            '    _dead = json_extract_scalar(_raw_log, "$.never")\n'
            "| alter\n"
            "    xdm.event.id = _used\n"
            ";\n"
        )
        ids = self._ids(source)
        self.assertNotIn("ERR-019", ids)

    def test_err019_fires_on_gc_raw(self):
        source = (
            "[MODEL: dataset=demo_gc_raw]\n"
            "alter\n"
            '    _used = json_extract_scalar(_raw_log, "$.id"),\n'
            '    _dead = json_extract_scalar(_raw_log, "$.never")\n'
            "| alter\n"
            "    xdm.event.id = _used\n"
            ";\n"
        )
        self.assertIn("ERR-019", self._ids(source))

    def test_err025_silent_on_plain_raw(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "alter\n"
            '    _note = json_extract_scalar(_raw_log, "$.note")\n'
            "| alter\n"
            '    xdm.event.description = concat("Note: ", _note)\n'
            ";\n"
        )
        self.assertNotIn("ERR-025", self._ids(source))


class TestWarn037SeverityLogLevel(unittest.TestCase):
    """WARN-037 fires on a log-level word in a VALUE position of an
    xdm.alert.severity assignment, but NOT on a comparison condition that
    tests for that word (the correct banding input)."""

    def _w37(self, source: str) -> list:
        return [v for v in lint(source) if v["rule_id"] == "WARN-037"]

    def test_value_position_fires(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    _level = json_extract_scalar(_raw_log, "$.level")\n'
            "| alter\n"
            "    xdm.alert.severity = if(\n"
            '        _level = "warning", "Warning",\n'
            '        _level != null, _level)\n'
            ";\n"
        )
        self.assertEqual(len(self._w37(source)), 1)

    def test_condition_only_is_silent(self):
        # The log-level word appears ONLY as a comparison input; the result
        # is a proper band. This is the correct banding and must not fire.
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    _level = json_extract_scalar(_raw_log, "$.level")\n'
            "| alter\n"
            "    xdm.alert.severity = if(\n"
            '        _level = "warning", "Medium",\n'
            '        _level = "error", "High",\n'
            '        _level != null, "Low")\n'
            ";\n"
        )
        self.assertEqual(self._w37(source), [])

    def test_direct_assignment_fires(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    _level = json_extract_scalar(_raw_log, "$.level")\n'
            "| alter\n"
            '    xdm.alert.severity = "Error"\n'
            ";\n"
        )
        self.assertEqual(len(self._w37(source)), 1)

    def test_substring_value_not_flagged(self):
        # A descriptive value that merely contains a log-level word is fine.
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    _n = json_extract_scalar(_raw_log, "$.n")\n'
            "| alter\n"
            '    xdm.alert.subcategory = "Error Page Probe",\n'
            "    xdm.alert.severity = if(_n != null, \"High\")\n"
            ";\n"
        )
        self.assertEqual(self._w37(source), [])


class TestWorkedExamplesLintClean(unittest.TestCase):
    """Behaviour-parity guard: every shipped worked-example rule must lint
    clean (zero error-severity findings). This is the bundle's gold
    standard, so a future rule that mis-fires on a real production rule is
    caught here."""

    def _model_rule(self, md_path: Path) -> str:
        lines = md_path.read_text(encoding="utf-8").splitlines()
        start = next(
            (i for i, ln in enumerate(lines) if ln.startswith("[MODEL:")), None
        )
        if start is None:
            return ""
        end = next(
            (j for j in range(start, len(lines)) if lines[j].strip() == "```"),
            len(lines),
        )
        return "\n".join(lines[start:end]) + "\n"

    def test_all_worked_examples_clean(self):
        we_dir = bundle_root() / "references" / "worked-examples"
        md_files = sorted(we_dir.glob("*.md"))
        self.assertGreaterEqual(len(md_files), 5, "expected 5 walkthroughs")
        for md in md_files:
            rule = self._model_rule(md)
            if not rule.strip():
                continue
            with self.subTest(example=md.name):
                errors = [
                    v for v in lint(rule) if v["severity"] == "error"
                ]
                self.assertEqual(
                    errors,
                    [],
                    f"{md.name}: worked-example rule should lint clean, "
                    f"got {[(v['rule_id'], v['line']) for v in errors]}",
                )


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
