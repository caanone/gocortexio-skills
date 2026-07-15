# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the syslog envelope layer (references/syslog-envelope.md).

Two halves:

  lint   -- WARN-040 (vendor-anchored / positional header) and WARN-041
            (PRI captured but its severity discarded) fire on the bad
            fixtures and stay silent on the canonical Stage 0 idiom.
  verify -- the offline verifier proves the priority decode is exact:
            <134> -> severity 6 (Informational), <12> -> severity 4
            (Warning, which only holds if to_integer truncates rather
            than rounds), and a PRI-stripped record degrades to nulls.
"""

from __future__ import annotations

import importlib.util
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


_lint = _load("lint_rule")
_verify = _load("verify_rule")


def _ids(source: str) -> list:
    return [v["rule_id"] for v in _lint.lint(source)]


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class TestSyslogLint(unittest.TestCase):
    def test_canonical_stage0_is_clean(self):
        ids = _ids(_read("syslog_envelope.xql"))
        self.assertNotIn("WARN-040", ids)
        self.assertNotIn("WARN-041", ids)
        errors = [v for v in _lint.lint(_read("syslog_envelope.xql"))
                  if v["severity"] == "error"]
        self.assertEqual(errors, [], f"canonical envelope has errors: {errors}")

    def test_vendor_anchored_header_fires_warn040(self):
        ids = _ids(_read("warn040_vendor_anchored_header.xql"))
        self.assertIn("WARN-040", ids)
        # The vendor-anchored fixture does not capture the PRI, so the
        # discarded-priority check must stay quiet.
        self.assertNotIn("WARN-041", ids)

    def test_pri_without_severity_fires_warn041(self):
        ids = _ids(_read("warn041_pri_no_severity.xql"))
        self.assertIn("WARN-041", ids)
        # Its host capture is PRI-anchored, so WARN-040 must stay quiet.
        self.assertNotIn("WARN-040", ids)

    def test_non_syslog_rule_is_untouched(self):
        ids = _ids(_read("clean_rule.xql"))
        self.assertNotIn("WARN-040", ids)
        self.assertNotIn("WARN-041", ids)

    def test_warn040_silent_when_pri_anchored(self):
        # The canonical host capture is relay-aware (greedy ^.* prefix to the
        # innermost origin header) and must not trip WARN-040.
        rule = (
            "[MODEL: dataset=demo_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            '    _host = arrayindex(regextract(_raw_log, '
            '"^.*<\\d{1,3}>[A-Za-z]{3}\\s+\\d+\\s+[\\d:]+\\s+(\\S+)\\s"), 0)\n'
            "| alter\n"
            '    xdm.observer.vendor = "Acme",\n'
            '    xdm.event.type = "ALERT",\n'
            "    xdm.observer.name = _host\n;\n"
        )
        ids = _ids(rule)
        self.assertNotIn("WARN-040", ids)
        # The relay-aware envelope host is not a prepend-fragile body capture.
        self.assertNotIn("WARN-047", ids)


class TestSyslogPriorityDecode(unittest.TestCase):
    """Run the canonical fixture over the three sample records and pin the
    decoded values. These are the Step 2 de-risk expectations."""

    def setUp(self):
        self.rule = _read("syslog_envelope.xql")
        text = _read("syslog_envelope.jsonl")
        self.records = _verify._load_records(text)
        self.assertEqual(len(self.records), 3)

    def _run(self, idx: int) -> dict:
        return _verify.evaluate_rule(self.rule, self.records[idx])

    def test_rfc3164_pri134_informational(self):
        out = self._run(0)
        self.assertEqual(out["xdm.observer.name"], "fw01")
        self.assertEqual(out["xdm.event.id"], "6")  # severity 6
        self.assertEqual(
            out["xdm.event.log_level"], "XDM_CONST.LOG_LEVEL_INFORMATIONAL"
        )
        self.assertEqual(out["xdm.alert.severity"], "Low")

    def test_rfc5424_pri12_warning_proves_truncation(self):
        out = self._run(1)
        self.assertEqual(out["xdm.observer.name"], "fw02")
        # 12 / 8 = 1.5; only truncation (not rounding) yields severity 4.
        self.assertEqual(out["xdm.event.id"], "4")
        self.assertEqual(
            out["xdm.event.log_level"], "XDM_CONST.LOG_LEVEL_WARNING"
        )
        self.assertEqual(out["xdm.alert.severity"], "Medium")

    def test_stripped_priority_degrades_to_null(self):
        out = self._run(2)
        # No <NNN>: the PRI-anchored captures and the decode all yield null.
        self.assertIsNone(out["xdm.observer.name"])
        self.assertIsNone(out["xdm.event.log_level"])
        self.assertIsNone(out["xdm.alert.severity"])
        self.assertIsNone(out["xdm.event.id"])
        # A non-envelope field still populates, proving graceful degradation.
        self.assertEqual(out["xdm.observer.vendor"], "Acme")

    def test_rfc5424_nil_hostname_never_mapped(self):
        # RFC 5424 permits the NILVALUE "-" for HOSTNAME. The guard stage
        # nulls it, so a hidden host can never leak a literal "-" into
        # xdm.observer.name; the priority decode is unaffected.
        record = "<134>1 2026-06-18T12:34:56Z - app 123 - - body here"
        out = _verify.evaluate_rule(self.rule, record)
        self.assertIsNone(out["xdm.observer.name"])
        self.assertEqual(
            out["xdm.event.log_level"], "XDM_CONST.LOG_LEVEL_INFORMATIONAL"
        )
        self.assertEqual(out["xdm.event.id"], "6")

    def test_relay_prepend_captures_origin_not_relay(self):
        # An intermediate relay prepends its own <PRI> ts host in front of
        # the original line. The relay-aware Stage 0 must recover the ORIGIN
        # host and the ORIGIN priority, not the relay's.
        relayed = (
            "<190>Jun 30 12:00:10 relay01 "
            "<134>Jun 30 12:00:04 originhost app: login ok"
        )
        out = _verify.evaluate_rule(self.rule, relayed)
        self.assertEqual(out["xdm.observer.name"], "originhost")  # not relay01
        self.assertEqual(out["xdm.event.id"], "6")  # origin PRI 134 -> sev 6
        self.assertEqual(
            out["xdm.event.log_level"], "XDM_CONST.LOG_LEVEL_INFORMATIONAL"
        )

    def test_direct_line_still_captures_host(self):
        # The greedy prefix is byte-identical on a direct single-header line.
        direct = "<134>Jun 30 12:00:04 originhost app: login ok"
        out = _verify.evaluate_rule(self.rule, direct)
        self.assertEqual(out["xdm.observer.name"], "originhost")
        self.assertEqual(out["xdm.event.id"], "6")


if __name__ == "__main__":
    unittest.main()
