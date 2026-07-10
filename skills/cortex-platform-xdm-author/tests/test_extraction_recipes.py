# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the extraction-recipe layer (references/extraction-recipes.md).

Each recipe is a complete MODEL rule that must (a) lint with zero
error-severity findings and (b) extract the pinned values from its sample
line through the offline verifier. This guarantees every recipe shipped
in the reference is provably correct, not merely plausible. A final test
asserts the reference file actually carries each recipe, so the doc and
the verified rules cannot silently drift apart.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _helpers import bundle_root  # noqa: E402

SCRIPTS = bundle_root() / "scripts"
RECIPES_DOC = bundle_root() / "references" / "extraction-recipes.md"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


_lint = _load("lint_rule")
_verify = _load("verify_rule")


# name -> (rule, sample line, {expected xdm target: value})
RECIPES = {
    "kv": (
        r'''[MODEL: dataset=vendor_kv_raw]
filter
    _raw_log != null
| alter
    _user = arrayindex(regextract(_raw_log, "\buser=([^\s]+)"), 0),
    _msg = arrayindex(regextract(_raw_log, "msg=\"([^\"]*)\""), 0)
| alter
    xdm.source.user.username = _user,
    xdm.event.description = _msg
;''',
        'ts=2026-07-09 user=alice.admin action=login msg="Login succeeded"',
        {"xdm.source.user.username": "alice.admin",
         "xdm.event.description": "Login succeeded"},
    ),
    "tuple": (
        r'''[MODEL: dataset=vendor_fw_raw]
filter
    _raw_log != null
| alter
    _src_ip = arrayindex(regextract(_raw_log, "src=(\d{1,3}(?:\.\d{1,3}){3})"), 0),
    _src_port = arrayindex(regextract(_raw_log, "src=\d{1,3}(?:\.\d{1,3}){3}:(\d{1,5})"), 0),
    _dst_ip = arrayindex(regextract(_raw_log, "dst=(\d{1,3}(?:\.\d{1,3}){3})"), 0)
| alter
    xdm.source.ipv4 = _src_ip,
    xdm.source.port = to_integer(to_number(_src_port)),
    xdm.target.ipv4 = _dst_ip
;''',
        'action=accept src=10.0.0.5:51000 dst=93.184.216.34:443 proto=tcp',
        {"xdm.source.ipv4": "10.0.0.5", "xdm.source.port": 51000,
         "xdm.target.ipv4": "93.184.216.34"},
    ),
    "cef": (
        r'''[MODEL: dataset=vendor_cef_raw]
filter
    _raw_log != null
| alter
    _cef_name = arrayindex(split(_raw_log, "|"), 5),
    _suser = arrayindex(regextract(_raw_log, "suser=([^\s]+)"), 0)
| alter
    xdm.event.original_event_type = _cef_name,
    xdm.source.user.username = _suser
;''',
        'CEF:0|Acme|Box|1.0|100|User login|5|src=10.0.0.5 suser=alice',
        {"xdm.event.original_event_type": "User login",
         "xdm.source.user.username": "alice"},
    ),
    "leef": (
        r'''[MODEL: dataset=vendor_leef_raw]
filter
    _raw_log != null
| alter
    _leef_evt = arrayindex(split(_raw_log, "|"), 4),
    _usr = arrayindex(regextract(_raw_log, "usrName=([^\s\t]+)"), 0)
| alter
    xdm.event.original_event_type = _leef_evt,
    xdm.source.user.username = _usr
;''',
        'LEEF:2.0|Acme|Box|1.0|4624|usrName=alice src=10.0.0.5',
        {"xdm.event.original_event_type": "4624",
         "xdm.source.user.username": "alice"},
    ),
    "syslog3164": (
        r'''[MODEL: dataset=vendor_nix_raw]
filter
    _raw_log != null
| alter
    _host = arrayindex(regextract(_raw_log, "^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)"), 0),
    _proc = arrayindex(regextract(_raw_log, "(\w+)\[\d+\]:"), 0),
    _pid = arrayindex(regextract(_raw_log, "\[(\d+)\]:"), 0)
| alter
    xdm.observer.name = _host,
    xdm.source.process.name = _proc,
    xdm.source.process.pid = to_integer(to_number(_pid))
;''',
        'Jun 19 09:51:59 host01 sshd[1234]: Accepted password for alice',
        {"xdm.observer.name": "host01", "xdm.source.process.name": "sshd",
         "xdm.source.process.pid": 1234},
    ),
    "scalars": (
        r'''[MODEL: dataset=vendor_text_raw]
filter
    _raw_log != null
| alter
    _ip = arrayindex(regextract(_raw_log, "\b(\d{1,3}(?:\.\d{1,3}){3})\b"), 0),
    _mac = arrayindex(regextract(_raw_log, "\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b"), 0),
    _email = arrayindex(regextract(_raw_log, "\b([\w.+-]+@[\w.-]+\.\w+)\b"), 0)
| alter
    xdm.source.ipv4 = _ip,
    xdm.source.host.mac_addresses = arraycreate(_mac),
    xdm.source.user.upn = _email
;''',
        'Login from 10.0.0.5 (aa:bb:cc:dd:ee:ff) by alice@corp.example.com',
        {"xdm.source.ipv4": "10.0.0.5",
         "xdm.source.user.upn": "alice@corp.example.com"},
    ),
}


class TestExtractionRecipes(unittest.TestCase):
    def test_recipes_lint_clean(self):
        for name, (rule, _s, _e) in RECIPES.items():
            errs = [v for v in _lint.lint(rule) if v["severity"] == "error"]
            self.assertEqual(errs, [], f"{name}: {[v['rule_id'] for v in errs]}")

    def test_recipes_extract_expected_values(self):
        for name, (rule, sample, expected) in RECIPES.items():
            out = _verify.evaluate_rule(rule, sample)
            for path, want in expected.items():
                self.assertEqual(
                    out.get(path), want,
                    f"{name}: {path} got {out.get(path)!r}, want {want!r}",
                )

    def test_mac_recipe_wraps_array(self):
        # The MAC leaf is an array field; the recipe must wrap it.
        out = _verify.evaluate_rule(*RECIPES["scalars"][:2])
        self.assertEqual(
            out.get("xdm.source.host.mac_addresses"), ["aa:bb:cc:dd:ee:ff"]
        )

    def test_doc_carries_every_recipe(self):
        # The reference and these verified rules must not drift apart: each
        # recipe's dataset header must appear verbatim in the doc.
        doc = RECIPES_DOC.read_text(encoding="utf-8")
        for name, (rule, _s, _e) in RECIPES.items():
            header = rule.splitlines()[0]  # [MODEL: dataset=..._raw]
            self.assertIn(header, doc, f"{name}: {header} missing from doc")


if __name__ == "__main__":
    unittest.main()
