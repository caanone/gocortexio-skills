# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for ``scripts/verify_rule.py``.

The verifier runs a MODEL rule over a sample offline. These tests pin the
evaluator subset that matters: json_extract_scalar + nested paths, the
null guard, banded if-chains, the arrow operator, arraymap / arrayfilter
with @element, the filter stage, and the --expect diff. Unsupported
constructs must raise rather than guess.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _helpers import bundle_root  # noqa: E402

SCRIPTS = bundle_root() / "scripts"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


_v = _load("verify_rule")


PATTERN_A = (
    "[MODEL: dataset=acme_demo_raw]\n"
    "filter\n"
    "    _raw_log != null\n"
    "| alter\n"
    '    _id = json_extract_scalar(_raw_log, "$.event_id"),\n'
    '    _ip = json_extract_scalar(_raw_log, "$.client.ip"),\n'
    '    _score = to_number(json_extract_scalar(_raw_log, "$.risk_score")),\n'
    '    _outcome = json_extract_scalar(_raw_log, "$.outcome")\n'
    "| alter\n"
    "    _severity = if(\n"
    '        _score >= 80, "Critical",\n'
    '        _score >= 50, "High",\n'
    '        _score >= 30, "Medium",\n'
    '        _score != null, "Low")\n'
    "| alter\n"
    '    xdm.observer.vendor = "Acme",\n'
    "    xdm.event.id = _id,\n"
    "    xdm.source.ipv4 = _ip,\n"
    "    xdm.alert.severity = _severity,\n"
    "    xdm.event.outcome = if(_outcome = \"ok\", XDM_CONST.OUTCOME_SUCCESS, "
    "XDM_CONST.OUTCOME_FAILED)\n"
    ";\n"
)


class TestEvaluator(unittest.TestCase):
    def test_nested_extract_and_banding(self):
        rec = {"event_id": "e1", "client": {"ip": "10.0.0.5"},
               "risk_score": 92, "outcome": "ok"}
        out = _v.evaluate_rule(PATTERN_A, rec)
        self.assertEqual(out["xdm.event.id"], "e1")
        self.assertEqual(out["xdm.source.ipv4"], "10.0.0.5")
        self.assertEqual(out["xdm.alert.severity"], "Critical")
        self.assertEqual(out["xdm.event.outcome"], "XDM_CONST.OUTCOME_SUCCESS")

    def test_band_medium_and_failed(self):
        rec = {"event_id": "e2", "client": {"ip": "10.0.0.9"},
               "risk_score": 40, "outcome": "bad"}
        out = _v.evaluate_rule(PATTERN_A, rec)
        self.assertEqual(out["xdm.alert.severity"], "Medium")
        self.assertEqual(out["xdm.event.outcome"], "XDM_CONST.OUTCOME_FAILED")

    def test_filter_drops_record(self):
        rule = (
            "[MODEL: dataset=demo_raw]\n"
            'filter\n    _raw_log = null\n'
            "| alter\n    xdm.event.id = \"x\"\n;\n"
        )
        self.assertIsNone(_v.evaluate_rule(rule, {"a": 1}))

    def test_arrow_arraymap_arrayfilter_with_element(self):
        rule = (
            "[MODEL: dataset=demo_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            "    _offender_ip = arrayindex(arrayfilter(arraymap(participants -> [],\n"
            '        if("@element" -> role = "offender", "@element" -> ip, null)),\n'
            '        "@element" != null), 0),\n'
            '    _cats = arraystring(categories -> [], ", ")\n'
            "| alter\n"
            "    xdm.source.ipv4 = _offender_ip,\n"
            '    xdm.event.description = concat("Cats: ", _cats)\n'
            ";\n"
        )
        rec = {
            "participants": [
                {"role": "victim", "ip": "10.0.0.1"},
                {"role": "offender", "ip": "203.0.113.7"},
            ],
            "categories": ["brute", "dos"],
        }
        out = _v.evaluate_rule(rule, rec)
        self.assertEqual(out["xdm.source.ipv4"], "203.0.113.7")
        self.assertEqual(out["xdm.event.description"], "Cats: brute, dos")

    def test_json_string_column_cast(self):
        # categories arrives as a JSON STRING; `-> []` must parse it.
        rule = (
            "[MODEL: dataset=demo_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            '    _joined = arraystring(categories -> [], "|")\n'
            "| alter\n"
            "    xdm.event.description = _joined\n;\n"
        )
        rec = {"categories": "[\"a\",\"b\"]"}
        out = _v.evaluate_rule(rule, rec)
        self.assertEqual(out["xdm.event.description"], "a|b")

    def test_coalesce_first_non_null(self):
        rule = (
            "[MODEL: dataset=demo_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            "    xdm.source.user.username = coalesce("
            'json_extract_scalar(_raw_log, "$.a"), '
            'json_extract_scalar(_raw_log, "$.b"))\n;\n'
        )
        out = _v.evaluate_rule(rule, {"b": "bob"})
        self.assertEqual(out["xdm.source.user.username"], "bob")

    def test_unsupported_function_raises(self):
        rule = (
            "[MODEL: dataset=demo_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n    xdm.event.id = nonexistent_fn(_raw_log)\n;\n"
        )
        with self.assertRaises(_v.UnsupportedConstruct):
            _v.evaluate_rule(rule, {"a": 1})


class TestCli(unittest.TestCase):
    def _write(self, name: str, text: str) -> Path:
        p = Path(self._dir.name) / name
        p.write_text(text, encoding="utf-8")
        return p

    def setUp(self):
        import tempfile
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.rule = self._write("rule.xql", PATTERN_A)
        self.sample = self._write(
            "sample.jsonl",
            '{"event_id":"e1","client":{"ip":"10.0.0.5"},"risk_score":92,"outcome":"ok"}\n',
        )

    def test_cli_json_output(self):
        cp = subprocess.run(
            [sys.executable, str(SCRIPTS / "verify_rule.py"),
             str(self.rule), str(self.sample)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        parsed = json.loads(cp.stdout)
        self.assertEqual(parsed[0]["xdm.alert.severity"], "Critical")

    def test_cli_expect_match(self):
        expect = self._write(
            "expect.json",
            '[{"xdm.alert.severity":"Critical","xdm.source.ipv4":"10.0.0.5"}]',
        )
        cp = subprocess.run(
            [sys.executable, str(SCRIPTS / "verify_rule.py"),
             str(self.rule), str(self.sample), "--expect", str(expect)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)

    def test_cli_expect_mismatch_exits_one(self):
        expect = self._write(
            "expect.json", '[{"xdm.alert.severity":"Low"}]'
        )
        cp = subprocess.run(
            [sys.executable, str(SCRIPTS / "verify_rule.py"),
             str(self.rule), str(self.sample), "--expect", str(expect)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(cp.returncode, 1)
        self.assertIn("mismatch", cp.stderr)

    def test_cli_missing_file_exits_two(self):
        cp = subprocess.run(
            [sys.executable, str(SCRIPTS / "verify_rule.py"),
             "/nope.xql", str(self.sample)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(cp.returncode, 2)


class TestRecordLevelClassification(unittest.TestCase):
    """Worked example 08 must classify PER RECORD: an auth shape gets the
    authentication tag, a command-accounting record becomes a process
    event with the command on target.process.command_line and NO auth
    tag, and an unrecognised line falls through to the catch-all."""

    def _rule(self) -> str:
        import re
        doc = (
            bundle_root() / "references" / "worked-examples"
            / "08-cisco-tacacs-aaa-multi-shape.md"
        ).read_text(encoding="utf-8")
        return re.findall(r"```\n(\[MODEL:.*?\n;)", doc, re.DOTALL)[0]

    def test_auth_shape(self):
        line = ('<14>Jun 19 09:50:01 aaa01 tacacsd[10]: type=AUTHENTICATION '
                'action=PERMIT user="bob" src_ip=10.0.35.9 dvc_ip=10.0.34.10')
        out = _v.evaluate_rule(self._rule(), line)
        self.assertEqual(out["xdm.event.type"], "authentication")
        self.assertEqual(out["xdm.event.tags"],
                         ["XDM_CONST.EVENT_TAG_AUTHENTICATION"])

    def test_command_accounting_is_process(self):
        line = ('<14>Jun 19 09:51:59 aaa01 tacacsd[25]: type=ACCOUNTING '
                'action=Stop user="alice" dvc_ip=10.0.34.10 '
                'cmd="show bgp neighbors"')
        out = _v.evaluate_rule(self._rule(), line)
        self.assertEqual(out["xdm.event.type"], "process")
        self.assertIsNone(out["xdm.event.tags"])
        self.assertEqual(out["xdm.target.process.command_line"],
                         "show bgp neighbors")
        self.assertEqual(out["xdm.event.operation"],
                         "XDM_CONST.OPERATION_TYPE_AUDIT")
        self.assertIsNone(out["xdm.event.outcome"])

    def test_unrecognised_line_catch_all(self):
        line = ('<14>Jun 19 09:52:10 aaa01 tacacsd[7]: Inconsistent lengths '
                'in PostSearchHook createreturnattrs')
        out = _v.evaluate_rule(self._rule(), line)
        self.assertEqual(out["xdm.event.type"], "GOCORTEX_UNMODELLED")
        self.assertIsNone(out["xdm.event.tags"])
        self.assertEqual(out["xdm.event.original_event_type"],
                         "GOCORTEX_UNMODELLED")


class TestBackslashStringSplit(unittest.TestCase):
    """A regex string literal that ends in an even run of backslashes
    (a Windows DOMAIN\\user split ends `...\\\\"`) must not swallow the
    assignment boundary in _split_assignments -- the escaped-backslash-
    before-quote case."""

    def test_domain_user_split(self):
        rule = (
            "[MODEL: dataset=win_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            '    tmp_u = json_extract_scalar(_raw_log, "$.User")\n'
            "| alter\n"
            '    xdm.source.user.domain = arrayindex(regextract(to_string(tmp_u), "^([^\\\\\\\\]+)\\\\\\\\"), 0),\n'
            '    xdm.source.user.username = arrayindex(regextract(to_string(tmp_u), "\\\\\\\\([^\\\\\\\\]+)$"), 0)\n'
            ";\n"
        )
        out = _v.evaluate_rule(rule, json.dumps({"User": "ACME\\alice"}))
        self.assertEqual(out["xdm.source.user.domain"], "ACME")
        self.assertEqual(out["xdm.source.user.username"], "alice")


if __name__ == "__main__":
    unittest.main()
