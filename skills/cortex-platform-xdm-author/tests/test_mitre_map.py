# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for ``scripts/mitre_map.py``.

The helper maps MITRE technique / tactic IDs or names to the
XDM_CONST.MITRE_* constants. The contract: every emitted constant exists
in the bundle's documented MITRE lists, unmapped inputs are reported and
omitted (never invented), and the emitted snippet embeds lint-clean.
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


_m = _load("mitre_map")
_schema = _load("_xdm_schema")
_lint = _load("lint_rule")


def _embed(snippet: str) -> str:
    body = "\n".join(
        ln for ln in snippet.splitlines() if not ln.strip().startswith("//")
    )
    return (
        "[MODEL: dataset=acme_demo_raw]\n"
        "filter\n    _raw_log != null\n"
        "| alter\n"
        '    tmp_mitre_ids = json_extract_array(_raw_log, "$.t")\n'
        "| alter\n"
        '    xdm.observer.vendor = "Acme",\n'
        '    xdm.event.type = "ALERT",\n'
        f"    {body}\n"
        ";\n"
    )


class TestCuratedTablesValid(unittest.TestCase):
    """Every curated mapping must reference a real bundle constant."""

    def test_all_tactic_consts_exist(self):
        known = _schema.all_consts()
        for tid, suffix in _m._TACTIC_IDS.items():
            self.assertIn(f"XDM_CONST.{suffix}", known, tid)

    def test_all_technique_consts_exist(self):
        known = _schema.all_consts()
        for tid, suffix in _m._TECHNIQUE_IDS.items():
            self.assertIn(f"XDM_CONST.{suffix}", known, tid)

    def test_fourteen_tactics(self):
        self.assertEqual(len(_m._TACTIC_IDS), 14)


class TestResolve(unittest.TestCase):
    def test_ids_resolve_and_drop_unknown(self):
        pairs, unmapped = _m.resolve_ids("technique", ["T1078", "T1059", "T9999"])
        consts = {c for _, c in pairs}
        self.assertIn("XDM_CONST.MITRE_TECHNIQUE_VALID_ACCOUNTS", consts)
        self.assertIn("XDM_CONST.MITRE_TECHNIQUE_COMMAND_AND_SCRIPTING_INTERPRETER", consts)
        self.assertIn("T9999", unmapped)

    def test_tactic_ids(self):
        pairs, unmapped = _m.resolve_ids("tactic", ["TA0006", "TA0002"])
        consts = {c for _, c in pairs}
        self.assertIn("XDM_CONST.MITRE_TACTIC_CREDENTIAL_ACCESS", consts)
        self.assertIn("XDM_CONST.MITRE_TACTIC_EXECUTION", consts)
        self.assertEqual(unmapped, [])

    def test_names_resolve(self):
        pairs, unmapped = _m.resolve_names("tactic", ["Credential Access", "Bogus"])
        consts = {c for _, c in pairs}
        self.assertIn("XDM_CONST.MITRE_TACTIC_CREDENTIAL_ACCESS", consts)
        self.assertIn("Bogus", unmapped)

    def test_never_invents(self):
        pairs, unmapped = _m.resolve_ids("technique", ["T9999"])
        self.assertEqual(pairs, [])
        self.assertIn("T9999", unmapped)


class TestRenderAndLint(unittest.TestCase):
    def test_array_snippet_lints_clean(self):
        pairs, unmapped = _m.resolve_ids("technique", ["T1078", "T1110"])
        snippet = _m.render(
            "xdm.alert.mitre_techniques", pairs, "tmp_mitre_ids", True, unmapped
        )
        self.assertIn("arraymap(tmp_mitre_ids, if(", snippet)
        errors = [v for v in _lint.lint(_embed(snippet)) if v["severity"] == "error"]
        self.assertEqual(errors, [], f"{errors}")

    def test_single_snippet_uses_arraycreate(self):
        pairs, _u = _m.resolve_ids("technique", ["T1078"])
        snippet = _m.render("xdm.alert.mitre_techniques", pairs, "_id", False, [])
        self.assertIn("arraycreate(if(", snippet)

    def test_render_empty_raises(self):
        with self.assertRaises(ValueError):
            _m.render("xdm.alert.mitre_techniques", [], "tmp_x", True, ["T9999"])


class TestCli(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPTS / "mitre_map.py"), *args],
            capture_output=True, text=True, check=False,
        )

    def test_cli_technique_ids(self):
        cp = self._run("--kind", "technique", "--ids", "T1078,T1059")
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("XDM_CONST.MITRE_TECHNIQUE_VALID_ACCOUNTS", cp.stdout)

    def test_cli_requires_input(self):
        cp = self._run("--kind", "tactic")
        self.assertEqual(cp.returncode, 1)

    def test_cli_all_unmapped_exits_one(self):
        cp = self._run("--kind", "technique", "--ids", "T9999")
        self.assertEqual(cp.returncode, 1)


class TestCrosswalkAndFuzzy(unittest.TestCase):
    """The full authoritative crosswalk resolves, and the fuzzy tactic
    emitter is a genuine multi-match into the array."""

    def test_crosswalk_full_and_valid(self):
        cw = _m._CROSSWALK
        self.assertGreaterEqual(len(cw.get("techniques", {})), 500)
        self.assertEqual(len(cw.get("tactics", {})), 14)
        self.assertEqual(len(cw.get("tactic_keywords", {})), 14)
        # Every crosswalk constant must be accepted by the const loader.
        known = _schema.all_consts()
        for suffix in cw["techniques"].values():
            self.assertIn(f"XDM_CONST.{suffix}", known, suffix)
        for suffix in cw["tactics"].values():
            self.assertIn(f"XDM_CONST.{suffix}", known, suffix)

    def test_noncurated_id_resolves(self):
        pairs, unmapped = _m.resolve_ids("technique", ["T1220"])
        self.assertEqual(
            [c for _, c in pairs],
            ["XDM_CONST.MITRE_TECHNIQUE_XSL_SCRIPT_PROCESSING"],
        )
        self.assertEqual(unmapped, [])

    def test_fuzzy_multi_match_into_array(self):
        verify = _load("verify_rule")
        chain = _m.render_fuzzy_tactics("xdm.alert.mitre_tactics", "tmp_category")
        rule = (
            "[MODEL: dataset=acme_demo_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            '    tmp_category = json_extract_scalar(_raw_log, "$.category")\n'
            "| alter\n"
            '    xdm.observer.vendor = "Acme",\n'
            '    xdm.event.type = "alert",\n'
            f"    {chain}\n"
            ";\n"
        )
        both = verify.evaluate_rule(
            rule, {"category": "Credential Access then Lateral Movement"}
        )
        self.assertEqual(
            both["xdm.alert.mitre_tactics"],
            [
                "XDM_CONST.MITRE_TACTIC_CREDENTIAL_ACCESS",
                "XDM_CONST.MITRE_TACTIC_LATERAL_MOVEMENT",
            ],
        )
        none = verify.evaluate_rule(rule, {"category": "benign sign-in"})
        self.assertEqual(none["xdm.alert.mitre_tactics"], [])
        # And it lints clean.
        errors = [v for v in _lint.lint(rule) if v["severity"] == "error"]
        self.assertEqual(errors, [], errors)


if __name__ == "__main__":
    unittest.main()
