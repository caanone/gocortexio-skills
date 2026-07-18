# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the Kerberos crosswalk asset and its renderer.

The Kerberos const groups are large numeric-keyed enums. The complete
code -> constant map for all six groups ships as
``assets/kerberos_crosswalk.json``; ``scripts/kerberos_map.py`` renders the
complete if()-chain for the two a 4768 / 4769 rule usually maps
(encryption type and error code). These tests pin crosswalk integrity, that
every member is known to the linter's const loader, and that the rendered
chains lint clean and verify end to end.
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


_kerb = _load("kerberos_map")
_schema = _load("_xdm_schema")
_lint = _load("lint_rule")
_verify = _load("verify_rule")

_EXPECTED = {
    "KERBEROS_ENCRYPTION_TYPE": 25,
    "KERBEROS_ERROR_CODE": 68,
    "KERBEROS_PRINCIPAL_TYPE": 9,
    "KERBEROS_KDC_OPTION": 20,
    "KERBEROS_MSG_TYPE": 12,
    "KERBEROS_PA_TYPE": 61,
}


def _wrap(chain: str, temp: str) -> str:
    return (
        "[MODEL: dataset=win_raw]\n"
        "filter\n    _raw_log != null\n"
        "| alter\n"
        f'    {temp} = to_integer(to_number(json_extract_scalar(_raw_log, "$.c")))\n'
        "| alter\n"
        f"    {chain}\n;\n"
    )


class TestCrosswalkIntegrity(unittest.TestCase):
    def setUp(self):
        self.data = read_json("assets/kerberos_crosswalk.json")
        self.groups = self.data["groups"]

    def test_group_sizes(self):
        for g, n in _EXPECTED.items():
            self.assertEqual(len(self.groups.get(g, {})), n, g)

    def test_codes_numeric_and_consts_wellformed(self):
        for g, codes in self.groups.items():
            for code, member in codes.items():
                self.assertTrue(code.isdigit(), f"{g}: non-numeric code {code!r}")
                self.assertRegex(member, rf"^XDM_CONST\.{g}_[A-Z0-9_]+$")

    def test_every_member_known_to_linter(self):
        consts = _schema.load_xdm_consts()
        for g, codes in self.groups.items():
            known = consts.get(g, set())
            missing = [m for m in codes.values() if m not in known]
            self.assertEqual(missing, [], f"{g}: not validated: {missing[:3]}")

    def test_logon_type_complete(self):
        # LOGON_TYPE is enumerated inline in xdm-const.md, not the asset.
        self.assertGreaterEqual(
            len(_schema.load_xdm_consts().get("LOGON_TYPE", set())), 12)


class TestRenderer(unittest.TestCase):
    def test_unknown_group_rejected(self):
        with self.assertRaises(ValueError):
            _kerb.render("nope")

    def test_encryption_chain_lints_and_verifies(self):
        chain = _kerb.render("encryption_type", "tmp_etype")
        rule = _wrap(chain, "tmp_etype")
        self.assertEqual(
            [v for v in _lint.lint(rule) if v["severity"] == "error"], [])
        out = _verify.evaluate_rule(rule, '{"c":"18"}')
        self.assertEqual(out["xdm.auth.kerberos_tgt.encryption_type"],
                         "XDM_CONST.KERBEROS_ENCRYPTION_TYPE_AES256_CTS_HMAC_SHA1_96")

    def test_error_chain_lints_and_verifies(self):
        chain = _kerb.render("error_code", "tmp_err")
        rule = _wrap(chain, "tmp_err")
        self.assertEqual(
            [v for v in _lint.lint(rule) if v["severity"] == "error"], [])
        out = _verify.evaluate_rule(rule, '{"c":"24"}')
        self.assertEqual(out["xdm.auth.kerberos_tgt.error_code"],
                         "XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_PREAUTH_FAILED")

    def test_custom_field(self):
        chain = _kerb.render("encryption_type", "tmp_e",
                             field="xdm.auth.kerberos_tgs.encryption_type")
        self.assertTrue(chain.startswith("xdm.auth.kerberos_tgs.encryption_type = if("))
        self.assertEqual(len(re.findall(r"XDM_CONST\.", chain)), 25)


if __name__ == "__main__":
    unittest.main()
