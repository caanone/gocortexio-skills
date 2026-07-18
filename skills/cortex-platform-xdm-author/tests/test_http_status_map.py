# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the complete HTTP status crosswalk and its renderer.

``xdm.network.http.response_code`` is const-typed over the full HTTP
status set, so the bundle ships the authoritative code -> constant map as
``assets/http_status_crosswalk.json`` and renders the complete if()-chain
with ``scripts/http_status_map.py``. These tests pin:

    * crosswalk integrity (numeric codes, well-formed constants, every
      member known to the linter's const loader),
    * the renderer emits one branch per code and no default branch,
    * the rendered chain lints clean, keeps WARN-048 silent, and verifies
      end to end over a sample.
"""

from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _helpers import bundle_root, read_json  # noqa: E402

SCRIPTS = bundle_root() / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


_http = _load("http_status_map")
_schema = _load("_xdm_schema")
_lint = _load("lint_rule")
_verify = _load("verify_rule")

_CONST_RE = re.compile(r"^XDM_CONST\.HTTP_RSP_CODE_[A-Z0-9_]+$")


def _wrap(chain: str, temp: str = "tmp_status") -> str:
    """Wrap a rendered response_code chain in a minimal MODEL rule that
    casts a token out of the raw line into the integer temp."""
    return (
        "[MODEL: dataset=web_raw]\n"
        "filter\n"
        "    _raw_log != null\n"
        "| alter\n"
        f'    {temp} = to_integer(to_number('
        'arrayindex(regextract(_raw_log, "\\" (\\\\d{3}) "), 0)))\n'
        "| alter\n"
        f"    {chain}\n"
        ";\n"
    )


class TestCrosswalkIntegrity(unittest.TestCase):
    def setUp(self):
        self.data = read_json("assets/http_status_crosswalk.json")
        self.codes = self.data["codes"]

    def test_wrapper_metadata(self):
        self.assertEqual(self.data["field"], "xdm.network.http.response_code")
        self.assertEqual(self.data["const_group"], "HTTP_RSP_CODE")

    def test_sixty_members(self):
        self.assertEqual(len(self.codes), 60)

    def test_codes_are_numeric(self):
        for code in self.codes:
            self.assertTrue(code.isdigit(), f"non-numeric code key {code!r}")

    def test_constants_well_formed(self):
        for member in self.codes.values():
            self.assertRegex(member, _CONST_RE)

    def test_no_duplicate_constants(self):
        members = list(self.codes.values())
        self.assertEqual(len(members), len(set(members)),
                         "duplicate constant in crosswalk")

    def test_every_member_known_to_linter(self):
        known = _schema.load_xdm_consts().get("HTTP_RSP_CODE", set())
        missing = [m for m in self.codes.values() if m not in known]
        self.assertEqual(missing, [], f"crosswalk members not validated: {missing}")

    def test_asset_matches_xdm_const_doc(self):
        # xdm-const.md enumerates the same full set (so the doc-consistency
        # test can validate every cited HTTP constant). Guard against drift.
        from _helpers import read_text
        in_http_fence = False
        in_fence = False
        doc_consts = set()
        for ln in read_text("references/xdm-const.md").splitlines():
            if ln.startswith("## "):
                in_http_fence = "HTTP response code" in ln
            if ln.startswith("```"):
                in_fence = not in_fence
                continue
            if in_http_fence and in_fence:
                m = re.match(r"^(XDM_CONST\.HTTP_RSP_CODE_[A-Z0-9_]+)", ln)
                if m:
                    doc_consts.add(m.group(1))
        self.assertEqual(doc_consts, set(self.codes.values()),
                         "xdm-const.md HTTP list has drifted from the crosswalk asset")

    def test_group_has_full_membership(self):
        # The merge must lift the whole crosswalk into the group, not just
        # the handful of codes enumerated in xdm-const.md.
        known = _schema.load_xdm_consts().get("HTTP_RSP_CODE", set())
        self.assertGreaterEqual(len(known), 60)


class TestRenderer(unittest.TestCase):
    def test_branch_per_code_no_default(self):
        codes = _http.load_crosswalk()
        chain = _http.render()
        # one XDM_CONST per code, none repeated, and no trailing bare default
        consts = re.findall(r"XDM_CONST\.HTTP_RSP_CODE_[A-Z0-9_]+", chain)
        self.assertEqual(len(consts), len(codes))
        self.assertEqual(len(set(consts)), len(codes))
        # closes on the last constant (no ", null)" default branch)
        self.assertTrue(chain.rstrip().endswith(")"))
        self.assertNotIn(", null)", chain)

    def test_codes_sorted_numerically(self):
        chain = _http.render()
        seen = [int(m) for m in re.findall(r"tmp_status = (\d+),", chain)]
        self.assertEqual(seen, sorted(seen))

    def test_custom_temp_and_field(self):
        chain = _http.render(temp="tmp_http_status",
                             field="xdm.network.http.response_code")
        self.assertIn("tmp_http_status = 200,", chain)
        self.assertTrue(chain.startswith("xdm.network.http.response_code = if("))

    def test_rendered_chain_lints_clean(self):
        rule = _wrap(_http.render())
        errors = [v for v in _lint.lint(rule) if v["severity"] == "error"]
        self.assertEqual(errors, [],
                         f"rendered chain should lint clean, got {errors}")

    def test_rendered_chain_silent_on_warn048(self):
        rule = _wrap(_http.render())
        w48 = [v for v in _lint.lint(rule) if v["rule_id"] == "WARN-048"]
        self.assertEqual(w48, [], "complete chain must not trip WARN-048")

    def test_rendered_chain_verifies(self):
        rule = _wrap(_http.render())
        for line, expected in (
            ('1.2.3.4 - - [x] "GET /a HTTP/1.1" 200 5', "XDM_CONST.HTTP_RSP_CODE_OK"),
            ('1.2.3.4 - - [x] "GET /a HTTP/1.1" 404 5', "XDM_CONST.HTTP_RSP_CODE_NOT_FOUND"),
            ('1.2.3.4 - - [x] "GET /a HTTP/1.1" 503 5',
             "XDM_CONST.HTTP_RSP_CODE_SERVICE_UNAVAILABLE"),
        ):
            out = _verify.evaluate_rule(rule, line)
            self.assertEqual(out.get("xdm.network.http.response_code"), expected,
                             f"status in {line!r}")


if __name__ == "__main__":
    unittest.main()
