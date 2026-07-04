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
import re
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
    return mod


_lint_mod = _load_lint()
lint = _lint_mod.lint


def _load_profiler():
    import importlib.util

    script = bundle_root() / "scripts" / "profile_log.py"
    spec = importlib.util.spec_from_file_location("profile_log", script)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _rule_ids(fixture_name: str) -> list:
    source = (FIXTURES / fixture_name).read_text(encoding="utf-8")
    return [v["rule_id"] for v in lint(source)]


_REF_FIELD_RE = re.compile(r"^\|\s*`(xdm\.[a-z0-9_.]+)`\s*\|")


def _mandatory_fields_from_reference(reference: Path) -> set:
    """Extract the mandatory authentication-story XDM fields from the
    canonical "Mandatory fields" table in the bundled reference doc.

    The table lists one backtick-quoted ``xdm.*`` field per row; the
    section ends at the next ``## `` heading. This is the in-bundle source
    of truth for the linter and profiler ``_AUTH_MANDATORY`` copies."""
    fields = set()
    in_section = False
    for line in reference.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            in_section = line.startswith("## Mandatory fields")
            continue
        if in_section:
            match = _REF_FIELD_RE.match(line)
            if match:
                fields.add(match.group(1))
    return fields


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
        ("warn038_missing_host_ipv4.xql", "WARN-038"),
        ("warn039_payload_in_description.xql", "WARN-039"),
        ("warn040_vendor_anchored_header.xql", "WARN-040"),
        ("warn041_pri_no_severity.xql", "WARN-041"),
        ("warn042_auth_mandatory.xql", "WARN-042"),
        ("warn043_network_mandatory.xql", "WARN-043"),
        ("info013_overmapping.xql", "INFO-013"),
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


class TestAuthMandatoryListsInSync(unittest.TestCase):
    """The linter and profiler each carry a copy of the authentication
    mandatory set. Both must stay identical to the canonical list so the
    advisory WARN-042 and the profiler checklist never drift apart.

    The canonical list ships inside the bundle as the "Mandatory fields"
    table in ``references/authentication-mapping.md``, so this drift-guard
    is fully self-contained and runs in a standalone checkout with no
    external file or environment configuration."""

    @classmethod
    def setUpClass(cls) -> None:
        reference = (
            bundle_root()
            / "references"
            / "authentication-mapping.md"
        )
        cls.expected = _mandatory_fields_from_reference(reference)
        # The reference heading promises exactly 12 mandatory fields; a
        # mismatch means the table itself drifted.
        if len(cls.expected) != 12:
            raise AssertionError(
                "expected 12 mandatory fields in the reference table, "
                "found %d" % len(cls.expected)
            )

    def test_linter_list_matches_reference(self):
        self.assertEqual(set(_lint_mod._AUTH_MANDATORY), self.expected)

    def test_profiler_list_matches_reference(self):
        prof = _load_profiler()
        self.assertEqual(set(prof._AUTH_MANDATORY), self.expected)


class TestWarn042AuthMandatory(unittest.TestCase):
    """WARN-042 auto-detects an authentication event and warns (never
    blocks) for each unmapped mandatory authentication-story field."""

    _COMPLETE_AUTH = """[MODEL: dataset=acme_idp_raw]
filter _raw_log != null
| alter
    _upn = json_extract_scalar(_raw_log, "$.user"),
    _src = json_extract_scalar(_raw_log, "$.src_ip"),
    _dst = json_extract_scalar(_raw_log, "$.dst_ip"),
    _sport = json_extract_scalar(_raw_log, "$.src_port"),
    _dport = json_extract_scalar(_raw_log, "$.dst_port"),
    _svc = json_extract_scalar(_raw_log, "$.service"),
    _action = json_extract_scalar(_raw_log, "$.action"),
    _result = json_extract_scalar(_raw_log, "$.result")
| alter
    xdm.event.type = "authentication",
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),
    xdm.event.operation = XDM_CONST.OPERATION_TYPE_AUTH_LOGIN,
    xdm.event.original_event_type = _action,
    xdm.event.outcome = if(_result = "success", XDM_CONST.OUTCOME_SUCCESS,
        _result != null, XDM_CONST.OUTCOME_FAILED),
    xdm.auth.service = _svc,
    xdm.source.user.upn = _upn,
    xdm.source.ipv4 = _src,
    xdm.source.port = to_integer(to_number(_sport)),
    xdm.target.ipv4 = _dst,
    xdm.target.port = to_integer(to_number(_dport)),
    xdm.network.ip_protocol = XDM_CONST.IP_PROTOCOL_TCP
;
"""

    def test_fires_for_each_missing_mandatory_field(self):
        ids = _rule_ids("warn042_auth_mandatory.xql")
        # The fixture maps 5 of 12 mandatory fields, so 7 should be flagged.
        self.assertEqual(ids.count("WARN-042"), 7, ids)

    def test_only_warning_severity_so_exit_stays_zero(self):
        source = (FIXTURES / "warn042_auth_mandatory.xql").read_text(
            encoding="utf-8"
        )
        sev = {v["severity"] for v in lint(source) if v["rule_id"] == "WARN-042"}
        self.assertEqual(sev, {"warning"})

    def test_silent_on_non_auth_rule(self):
        ids = _rule_ids("clean_rule.xql")
        self.assertNotIn("WARN-042", ids)

    def test_silent_when_all_mandatory_mapped(self):
        ids = [v["rule_id"] for v in lint(self._COMPLETE_AUTH)]
        self.assertNotIn("WARN-042", ids)

    def test_value_conformance_flags_forbidden_literals(self):
        # All 12 mandatory fields are present, so none should be flagged as
        # missing. Eight, however, carry a value the authentication story
        # forbids (event.type, event.operation, event.outcome, auth.service,
        # source.ipv4, target.ipv4, network.ip_protocol, and the bare
        # possibly-not-UPN-shaped identifier assigned to source.user.upn).
        source = (FIXTURES / "warn042_auth_bad_values.xql").read_text(
            encoding="utf-8"
        )
        vios = [v for v in lint(source) if v["rule_id"] == "WARN-042"]
        self.assertEqual(len(vios), 8, [v["message"] for v in vios])
        self.assertEqual({v["severity"] for v in vios}, {"warning"})

    def test_value_conformance_silent_on_temp_sourced_values(self):
        # The complete fixture maps auth.service and outcome from temps and
        # source.ipv4 from a temp. Value conformance must never second-guess
        # a runtime-resolved value, so it stays silent here.
        vios = [v for v in lint(self._COMPLETE_AUTH) if v["rule_id"] == "WARN-042"]
        self.assertEqual(vios, [])

    _DYNAMIC_AUTH = """[MODEL: dataset=acme_idp_raw]
filter _raw_log != null
| alter
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),
    xdm.event.type = event_type_col,
    xdm.event.operation = op_col,
    xdm.event.original_event_type = action_col,
    xdm.event.outcome = outcome_col,
    xdm.auth.service = svc_col,
    xdm.source.user.upn = upn_col,
    xdm.source.ipv4 = src_ip,
    xdm.source.port = to_integer(to_number(sport_col)),
    xdm.target.ipv4 = dst_ip,
    xdm.target.port = to_integer(to_number(dport_col)),
    xdm.network.ip_protocol = proto_col
;
"""

    def test_value_conformance_silent_on_bare_column_mappings(self):
        # Direct raw-column mappings (no leading underscore) are not static
        # literals. Value conformance must not mistake src_ip / proto_col
        # for hard-coded values, even though they are not temps.
        vios = [v for v in lint(self._DYNAMIC_AUTH) if v["rule_id"] == "WARN-042"]
        self.assertEqual(vios, [])

    _SIGNAL_ONLY_AUTH = """[MODEL: dataset=acme_idp_raw]
filter _raw_log != null
| alter
    xdm.event.original_event_type = "user.login",
    xdm.source.user.upn = user_col
;
"""

    def test_classifies_auth_from_event_signal_without_marker(self):
        # No explicit XDM marker (no EVENT_TAG_AUTHENTICATION,
        # OPERATION_TYPE_AUTH_*, or "authentication" in event.type), but
        # original_event_type carries an auth literal. WARN-042 must still
        # classify the rule as authentication and flag the unmapped
        # mandatory fields.
        vios = [v for v in lint(self._SIGNAL_ONLY_AUTH) if v["rule_id"] == "WARN-042"]
        self.assertTrue(vios, "signal-only auth rule should trigger WARN-042")
        self.assertEqual({v["severity"] for v in vios}, {"warning"})
        # original_event_type and source.user.upn are mapped; the rest of
        # the mandatory set is missing and must be reported.
        msgs = " ".join(v["message"] for v in vios)
        self.assertIn("xdm.event.outcome", msgs)
        self.assertIn("xdm.auth.service", msgs)

    def test_classifies_auth_from_operation_literal_signal(self):
        # The literal signal must work across every event-semantic field,
        # including xdm.event.operation carrying an auth literal.
        source = (
            "[MODEL: dataset=acme_idp_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    xdm.event.operation = "signin",\n'
            "    xdm.source.user.upn = user_col\n"
            ";\n"
        )
        vios = [v for v in lint(source) if v["rule_id"] == "WARN-042"]
        self.assertTrue(vios, "operation literal signal should trigger WARN-042")

    def test_no_auth_classification_without_signal_or_marker(self):
        # A MODEL rule with an event type that has no auth token and no
        # marker must never be classified as authentication.
        source = (
            "[MODEL: dataset=acme_web_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    xdm.event.original_event_type = "file.download",\n'
            "    xdm.source.user.upn = user_col\n"
            ";\n"
        )
        vios = [v for v in lint(source) if v["rule_id"] == "WARN-042"]
        self.assertEqual(vios, [])


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


class TestWarn038HostCompanion(unittest.TestCase):
    """WARN-038 fires when a named host has an IP but no ipv4_addresses
    companion, and stays silent once the companion is present."""

    def _w38(self, source: str) -> list:
        return [v for v in lint(source) if v["rule_id"] == "WARN-038"]

    def test_silent_when_companion_present(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    _asset = json_extract_scalar(_raw_log, "$.asset"),\n'
            '    _dst = json_extract_scalar(_raw_log, "$.dst")\n'
            "| alter\n"
            "    xdm.target.ipv4 = _dst,\n"
            "    xdm.target.host.hostname = _asset,\n"
            "    xdm.target.host.ipv4_addresses = if(_dst != null, "
            "arraycreate(_dst), null)\n"
            ";\n"
        )
        self.assertEqual(self._w38(source), [])

    def test_silent_when_no_hostname(self):
        # Only the IP, no named host -- nothing to companion.
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    _dst = json_extract_scalar(_raw_log, "$.dst")\n'
            "| alter\n"
            "    xdm.target.ipv4 = _dst\n"
            ";\n"
        )
        self.assertEqual(self._w38(source), [])


class TestInfo013OverMapping(unittest.TestCase):
    """INFO-013 fires on a temp spread across 3+ entity families, but not
    on the documented source/target mirror (two families), and not when
    the extra families are the event / observer metadata sinks."""

    def _i13(self, source: str) -> list:
        return [v for v in lint(source) if v["rule_id"] == "INFO-013"]

    def test_silent_on_source_target_mirror(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    _ip = json_extract_scalar(_raw_log, "$.ip")\n'
            "| alter\n"
            "    xdm.source.ipv4 = _ip,\n"
            "    xdm.target.ipv4 = _ip\n"
            ";\n"
        )
        self.assertEqual(self._i13(source), [])

    def test_silent_when_extra_family_is_event(self):
        # A URL legitimately lives in target + network + the event summary;
        # the event sink must not push it over the threshold.
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    _url = json_extract_scalar(_raw_log, "$.url")\n'
            "| alter\n"
            "    xdm.target.url = _url,\n"
            "    xdm.network.http.url = _url,\n"
            '    xdm.event.description = concat("URL: ", _url)\n'
            ";\n"
        )
        self.assertEqual(self._i13(source), [])

    def test_fires_on_three_entity_families(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    _thing = json_extract_scalar(_raw_log, "$.thing")\n'
            "| alter\n"
            "    xdm.source.user.username = _thing,\n"
            "    xdm.target.user.username = _thing,\n"
            "    xdm.alert.name = _thing\n"
            ";\n"
        )
        hits = self._i13(source)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "info")


class TestWarn039PayloadInDescription(unittest.TestCase):
    """WARN-039 fires when the whole payload (via _raw_log or
    to_json_string) is assigned to xdm.event.description, and stays silent
    on a proper concat() summary over scalar temps."""

    def _w39(self, source: str) -> list:
        return [v for v in lint(source) if v["rule_id"] == "WARN-039"]

    def test_fires_on_to_json_string(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    _d = json_extract_scalar(_raw_log, "$.d")\n'
            "| alter\n"
            "    xdm.event.description = to_json_string(detail)\n"
            ";\n"
        )
        self.assertEqual(len(self._w39(source)), 1)

    def test_silent_on_concat_summary(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    _act = json_extract_scalar(_raw_log, "$.action")\n'
            "| alter\n"
            "    xdm.observer.action = _act,\n"
            '    xdm.event.description = concat("Action: ", _act)\n'
            ";\n"
        )
        self.assertEqual(self._w39(source), [])


class TestNetworkMandatoryListsInSync(unittest.TestCase):
    """The linter and profiler each carry a copy of the network mandatory
    set. Both must stay identical to the canonical list -- the "Mandatory
    fields" table in ``references/network-mapping.md`` -- so the advisory
    WARN-043 and the profiler checklist never drift apart. Fully
    self-contained: runs in a standalone checkout."""

    @classmethod
    def setUpClass(cls) -> None:
        reference = bundle_root() / "references" / "network-mapping.md"
        cls.expected = _mandatory_fields_from_reference(reference)
        if len(cls.expected) != 20:
            raise AssertionError(
                "expected 20 mandatory fields in the network reference "
                "table, found %d" % len(cls.expected)
            )

    def test_linter_list_matches_reference(self):
        self.assertEqual(set(_lint_mod._NETWORK_MANDATORY), self.expected)

    def test_profiler_list_matches_reference(self):
        prof = _load_profiler()
        self.assertEqual(set(prof._NETWORK_MANDATORY), self.expected)


class TestWarn043NetworkMandatory(unittest.TestCase):
    """WARN-043 auto-detects a network event (conservatively: only the
    EVENT_TAG_NETWORK marker or a "network" event.type value) and warns,
    never blocks, per unmapped mandatory network-story field."""

    _COMPLETE_NETWORK = """[MODEL: dataset=acmefw_raw]
filter _raw_log != null
| alter
    _act = json_extract_scalar(_raw_log, "$.action"),
    _src = json_extract_scalar(_raw_log, "$.src_ip"),
    _dst = json_extract_scalar(_raw_log, "$.dst_ip"),
    _sport = json_extract_scalar(_raw_log, "$.src_port"),
    _dport = json_extract_scalar(_raw_log, "$.dst_port"),
    _sent = json_extract_scalar(_raw_log, "$.bytes_out"),
    _rcvd = json_extract_scalar(_raw_log, "$.bytes_in")
| alter
    xdm.observer.vendor = "AcmeFW",
    xdm.event.type = "network",
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK),
    xdm.event.outcome = if(_act = "allow", XDM_CONST.OUTCOME_SUCCESS, _act != null, XDM_CONST.OUTCOME_FAILED, XDM_CONST.OUTCOME_UNKNOWN),
    xdm.network.ip_protocol = XDM_CONST.IP_PROTOCOL_TCP,
    xdm.network.protocol_layers = arraycreate("TCP"),
    xdm.network.http.http_header.header = "",
    xdm.network.http.http_header.value = "",
    xdm.network.http.url_category = XDM_CONST.URL_CATEGORY_UNKNOWN,
    xdm.source.ipv4 = _src,
    xdm.source.ipv6 = "",
    xdm.source.is_internal_ip = if(incidr(_src, "10.0.0.0/8"), true, false),
    xdm.source.port = to_integer(to_number(_sport)),
    xdm.source.sent_bytes = to_integer(to_number(_sent)),
    xdm.source.host.device_id = "",
    xdm.target.ipv4 = _dst,
    xdm.target.ipv6 = "",
    xdm.target.is_internal_ip = if(incidr(_dst, "10.0.0.0/8"), true, false),
    xdm.target.port = to_integer(to_number(_dport)),
    xdm.target.sent_bytes = to_integer(to_number(_rcvd)),
    xdm.target.host.device_id = ""
;
"""

    def _w43(self, source: str) -> list:
        return [v for v in lint(source) if v["rule_id"] == "WARN-043"]

    def test_complete_rule_is_silent(self):
        self.assertEqual(self._w43(self._COMPLETE_NETWORK), [])

    def test_fires_per_missing_field(self):
        # The fixture maps type, tags and source.ipv4 -> 17 of 20 missing.
        source = (FIXTURES / "warn043_network_mandatory.xql").read_text(
            encoding="utf-8"
        )
        findings = self._w43(source)
        self.assertEqual(len(findings), 17, [f["message"] for f in findings])
        self.assertTrue(all(f["severity"] == "warning" for f in findings))

    def test_event_type_marker_alone_fires(self):
        # No tag, but event.type resolves to "network" -- still classified.
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    xdm.event.type = "network"\n;\n'
        )
        self.assertTrue(self._w43(source))

    def test_dual_rule_gets_both_advisories(self):
        source = (
            "[MODEL: dataset=vpn_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    _u = json_extract_scalar(_raw_log, "$.user")\n'
            "| alter\n"
            '    xdm.event.type = "authentication",\n'
            "    xdm.event.tags = arraycreate("
            "XDM_CONST.EVENT_TAG_AUTHENTICATION, "
            "XDM_CONST.EVENT_TAG_NETWORK),\n"
            "    xdm.source.user.upn = _u\n;\n"
        )
        ids = [v["rule_id"] for v in lint(source)]
        self.assertIn("WARN-042", ids)
        self.assertIn("WARN-043", ids)

    def test_duplicate_tags_assignment_flagged(self):
        source = (
            "[MODEL: dataset=vpn_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            "    xdm.event.tags = arraycreate("
            "XDM_CONST.EVENT_TAG_AUTHENTICATION),\n"
            "    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK)\n"
            ";\n"
        )
        dup = [v for v in self._w43(source) if "more than once" in v["message"]]
        self.assertEqual(len(dup), 1)

    def test_outcome_conformance_allows_unknown_pad(self):
        # OUTCOME_UNKNOWN is the documented network padding value; only a
        # const outside the network vocabulary is flagged.
        good = self._COMPLETE_NETWORK
        self.assertEqual(self._w43(good), [])
        bad = good.replace(
            "if(_act = \"allow\", XDM_CONST.OUTCOME_SUCCESS, _act != null, "
            "XDM_CONST.OUTCOME_FAILED, XDM_CONST.OUTCOME_UNKNOWN)",
            "XDM_CONST.OUTCOME_PARTIAL",
        )
        flagged = [v for v in self._w43(bad) if "OUTCOME_PARTIAL" in v["message"]]
        self.assertEqual(len(flagged), 1)

    def test_protocol_layers_scalar_literal_flagged(self):
        bad = self._COMPLETE_NETWORK.replace(
            'xdm.network.protocol_layers = arraycreate("TCP")',
            'xdm.network.protocol_layers = "TCP"',
        )
        flagged = [v for v in self._w43(bad) if "bare scalar" in v["message"]]
        self.assertEqual(len(flagged), 1)

    def test_non_network_rules_untouched(self):
        for fixture in ("clean_rule.xql", "warn042_auth_mandatory.xql"):
            with self.subTest(fixture=fixture):
                self.assertNotIn("WARN-043", _rule_ids(fixture))


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


class TestStoryMarkerEdgeCases(unittest.TestCase):
    """Edge-case guards for the story markers and value conformance."""

    def test_temp_names_do_not_fire_markers(self):
        # EC2: marker words are matched against quoted literals only -- a
        # temp named _network_type / _authentication_kind on the RHS must
        # not classify the rule into a story.
        base = (
            "[MODEL: dataset=x_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    {temp} = json_extract_scalar(_raw_log, "$.t")\n'
            "| alter\n"
            '    xdm.observer.vendor = "V",\n'
            "    xdm.event.type = {temp}\n;\n"
        )
        ids = _rule_ids_from(base.format(temp="_network_type"))
        self.assertNotIn("WARN-043", ids)
        ids = _rule_ids_from(base.format(temp="_authentication_kind"))
        self.assertNotIn("WARN-042", ids)
        # The literal forms must still classify.
        lit = base.replace("xdm.event.type = {temp}",
                           'xdm.event.type = "network"')
        self.assertIn("WARN-043", _rule_ids_from(lit.format(temp="_t")))

    def test_static_upn_flagged(self):
        # EC3: upn is the story correlation key -- a static or empty
        # literal is as damaging as leaving it unmapped.
        rule = (
            "[MODEL: dataset=x_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    _u = json_extract_scalar(_raw_log, "$.u")\n'
            "| alter\n"
            '    xdm.observer.vendor = "V",\n'
            '    xdm.event.type = "authentication",\n'
            '    xdm.source.user.upn = ""\n;\n'
        )
        hits = [v for v in lint(rule)
                if v["rule_id"] == "WARN-042"
                and "correlation key" in v["message"]]
        self.assertEqual(len(hits), 1, hits)
        # A raw-mapped upn is never second-guessed.
        ok = rule.replace('xdm.source.user.upn = ""',
                          "xdm.source.user.upn = _u")
        self.assertEqual(
            [v for v in lint(ok) if "correlation key" in v["message"]], []
        )

    def test_bare_identifier_upn_flagged(self):
        # The upn must ALWAYS be UPN-shaped: a bare identifier whose name
        # does not itself indicate a UPN source is flagged; UPN-named
        # identifiers and the shape-guard idiom stay silent.
        base = (
            "[MODEL: dataset=x_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    {t} = json_extract_scalar(_raw_log, "$.u")\n'
            "| alter\n"
            '    xdm.observer.vendor = "V",\n'
            '    xdm.event.type = "authentication",\n'
            "    xdm.source.user.upn = {rhs}\n;\n"
        )

        def shape_hits(t, rhs):
            return [v for v in lint(base.format(t=t, rhs=rhs))
                    if "UPN-shaped" in v["message"]]

        self.assertEqual(len(shape_hits("_user", "_user")), 1)
        self.assertEqual(len(shape_hits("_username", "_username")), 1)
        self.assertEqual(shape_hits("_upn", "_upn"), [])
        self.assertEqual(shape_hits("_email", "_email"), [])
        guard = ('if(_user contains "@", _user, _user != null, '
                 'concat(_user, "@localhost"))')
        self.assertEqual(shape_hits("_user", guard), [])

    def test_duplicate_tags_flagged_on_auth_only_rule(self):
        # EC7: the overwrite hazard exists without any network marker.
        rule = (
            "[MODEL: dataset=x_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    xdm.observer.vendor = "V",\n'
            '    xdm.event.type = "authentication",\n'
            "    xdm.event.tags = arraycreate("
            "XDM_CONST.EVENT_TAG_AUTHENTICATION),\n"
            "    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_MFA)\n;\n"
        )
        dups = [v for v in lint(rule) if "more than once" in v["message"]]
        self.assertEqual(len(dups), 1)
        self.assertEqual(dups[0]["rule_id"], "WARN-042")
        # On a dual rule the finding belongs to WARN-043 and is reported
        # exactly once, never doubled.
        dual = rule.replace("EVENT_TAG_MFA", "EVENT_TAG_NETWORK")
        dups2 = [v for v in lint(dual) if "more than once" in v["message"]]
        self.assertEqual(len(dups2), 1)
        self.assertEqual(dups2[0]["rule_id"], "WARN-043")


def _rule_ids_from(source: str) -> list:
    return [v["rule_id"] for v in lint(source)]


class TestMultiFormatExamplesFullyClean(unittest.TestCase):
    """The multi-format walkthroughs (06 Okta, 07 FortiGate, 08 TACACS+)
    are the story gold standards: EVERY rule block in them must lint with
    zero findings of ANY severity -- no WARN-042/043 stragglers, no
    envelope warnings -- not merely zero errors."""

    _EXAMPLES = (
        "06-okta-authentication-multi-format.md",
        "07-fortigate-network-multi-format.md",
        "08-cisco-tacacs-aaa-multi-shape.md",
    )

    def test_every_block_completely_clean(self):
        we_dir = bundle_root() / "references" / "worked-examples"
        for name in self._EXAMPLES:
            doc = (we_dir / name).read_text(encoding="utf-8")
            rules = re.findall(r"(\[MODEL:.*?;)", doc, re.DOTALL)
            self.assertTrue(rules, f"{name}: no MODEL blocks found")
            for i, rule in enumerate(rules):
                with self.subTest(example=name, block=i):
                    findings = lint(rule)
                    self.assertEqual(
                        findings,
                        [],
                        f"{name} block {i}: expected zero findings, got "
                        f"{[(v['rule_id'], v['line']) for v in findings]}",
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
