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
    _host = arrayindex(regextract(_raw_log, "^.*(?:<\d{1,3}>)?[A-Za-z]{3}\s+\d+\s+[\d:]+\s+(\S+)\s"), 0),
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
    "sros": (
        r'''[MODEL: dataset=vendor_sros_raw]
filter
    _raw_log != null
| alter
    _sros_event = arrayindex(regextract(_raw_log, "Base \w+-\w+-(\w+)"), 0),
    _sros_user = arrayindex(regextract(_raw_log, "\bUser (\S+)"), 0)
| alter
    xdm.event.original_event_type = _sros_event,
    xdm.source.user.username = _sros_user
;''',
        '<149>Jun 30 12:00:04 router1 tmnx: 470024 Base SECURITY-MAJOR-cli_user_login - User admin1 login from console',
        {"xdm.event.original_event_type": "cli_user_login",
         "xdm.source.user.username": "admin1"},
    ),
    "ios_bracket": (
        r'''[MODEL: dataset=vendor_ios_raw]
filter
    _raw_log != null
| alter
    _ios_event = arrayindex(regextract(_raw_log, "%([\w]+-\d-\w+):"), 0),
    _ios_user = arrayindex(regextract(_raw_log, "\[user: ?([^\]]+)\]"), 0),
    _ios_src = arrayindex(regextract(_raw_log, "\[Source: ?(\d{1,3}(?:\.\d{1,3}){3})\]"), 0)
| alter
    xdm.event.original_event_type = _ios_event,
    xdm.source.user.username = _ios_user,
    xdm.source.ipv4 = _ios_src
;''',
        '<190>Jun 30 12:00:04 sw1 %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin] [Source: 10.0.0.5] [localport: 22] at 12:00:04 UTC',
        {"xdm.event.original_event_type": "SEC_LOGIN-5-LOGIN_SUCCESS",
         "xdm.source.user.username": "admin",
         "xdm.source.ipv4": "10.0.0.5"},
    ),
    "vrp_paren_kv": (
        r'''[MODEL: dataset=vendor_vrp_raw]
filter
    _raw_log != null
| alter
    _vrp_event = arrayindex(regextract(_raw_log, "%%\d*\w+/\d/(\w+)"), 0),
    _vrp_user = arrayindex(regextract(_raw_log, "UserName=([^,)]+)"), 0),
    _vrp_ip = arrayindex(regextract(_raw_log, "IPAddress=([^,)]+)"), 0)
| alter
    xdm.event.original_event_type = _vrp_event,
    xdm.source.user.username = _vrp_user,
    xdm.source.ipv4 = _vrp_ip
;''',
        '<190>Jun 30 12:00:04 rtr1 %%01SSH/4/SSH_FAIL(l):Failed to login through SSH. (UserName=admin, IPAddress=10.0.0.5)',
        {"xdm.event.original_event_type": "SSH_FAIL",
         "xdm.source.user.username": "admin",
         "xdm.source.ipv4": "10.0.0.5"},
    ),
    "clf": (
        r'''[MODEL: dataset=vendor_clf_raw]
filter
    _raw_log != null
| alter
    _clf_ip = arrayindex(regextract(_raw_log, "^(\d{1,3}(?:\.\d{1,3}){3})"), 0),
    _clf_method = arrayindex(regextract(_raw_log, "\"(\w+) \S+ HTTP/\d"), 0),
    _clf_url = arrayindex(regextract(_raw_log, "\"\w+ (\S+) HTTP/\d"), 0),
    _clf_ua = arrayindex(regextract(_raw_log, "\"([^\"]*)\"\s*$"), 0)
| alter
    xdm.source.ipv4 = _clf_ip,
    xdm.network.http.method = _clf_method,
    xdm.network.http.url = _clf_url,
    xdm.source.user_agent = _clf_ua
;''',
        '10.0.0.5 - alice [30/Jun/2025:12:00:04 +0000] "GET /app/login HTTP/1.1" 200 1234 "https://portal.example.com/" "Mozilla/5.0 (Windows NT 10.0)"',
        {"xdm.source.ipv4": "10.0.0.5",
         "xdm.network.http.method": "GET",
         "xdm.network.http.url": "/app/login",
         "xdm.source.user_agent": "Mozilla/5.0 (Windows NT 10.0)"},
    ),
    "wlc_prepend": (
        r'''[MODEL: dataset=cisco_wlc_raw]
filter
    _raw_log != null
| alter
    _wlc_host     = arrayindex(regextract(_raw_log, "^.*<\d{1,3}>[A-Za-z]{3}\s+\d+\s+[\d:]+\s+(\S+)\s"), 0),
    _wlc_mnemonic = arrayindex(regextract(_raw_log, "%(\w+-\d-\w+):"), 0),
    _wlc_mac      = arrayindex(regextract(_raw_log, "for mobile ([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})"), 0)
| alter
    xdm.observer.name = _wlc_host,
    xdm.event.original_event_type = _wlc_mnemonic,
    xdm.source.host.mac_addresses = arraycreate(_wlc_mac)
;''',
        '<134>Jul 14 15:41:24 wlc-mgmt.example.net wlc01: *apfReceiveTask: Jul 14 15:41:24.640: %APF-6-USER_NAME_CREATED: [SS]apf_ms.c:9003 Username entry (3E-A8-8D-20-D1-1E) with length (17) created for mobile 3e:a8:8d:20:d1:1e',
        {"xdm.observer.name": "wlc-mgmt.example.net",
         "xdm.event.original_event_type": "APF-6-USER_NAME_CREATED",
         "xdm.source.host.mac_addresses": ["3e:a8:8d:20:d1:1e"]},
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

    def test_clf_recipe_on_tomcat_fixture(self):
        # The Combined Log Format recipe extracts HTTP fields from a real
        # Tomcat access-log fixture (a different line than the doc sample).
        fixture = (
            bundle_root() / "tests" / "fixtures" / "apache_tomcat_access.log"
        ).read_text(encoding="utf-8").splitlines()
        rule = RECIPES["clf"][0]
        out = _verify.evaluate_rule(rule, fixture[1])  # the POST /app/admin 403 line
        self.assertEqual(out.get("xdm.network.http.method"), "POST")
        self.assertEqual(out.get("xdm.network.http.url"), "/app/admin")
        self.assertEqual(out.get("xdm.source.ipv4"), "10.0.0.9")

    def test_recipe5_prepend_tolerant_across_arrival_shapes(self):
        # HARD RULE: the same source arrives no-PRI, with a PRI, and
        # relay-prepended -- the prepend-tolerant host must yield the origin
        # host (host01) in every form, and proc/pid are token-anchored.
        rule = RECIPES["syslog3164"][0]
        base = "sshd[1234]: Accepted password for alice"
        shapes = {
            "no-PRI": f"Jun 19 09:51:59 host01 {base}",
            "PRI": f"<134>Jun 19 09:51:59 host01 {base}",
            "relayed": (
                "<190>Jun 30 12:00:10 relay01 "
                f"<134>Jun 19 09:51:59 host01 {base}"
            ),
        }
        for name, line in shapes.items():
            out = _verify.evaluate_rule(rule, line)
            self.assertEqual(out.get("xdm.observer.name"), "host01", name)
            self.assertEqual(out.get("xdm.source.process.name"), "sshd", name)
            self.assertEqual(out.get("xdm.source.process.pid"), 1234, name)

    def test_wlc_recipe_direct_and_prepend_identical(self):
        # The WLC recipe extracts the identical mnemonic + MAC whether the
        # line is relay-prepended or direct off the box (host is only present
        # in the prepended envelope). Proves the hard rule end to end.
        rule = RECIPES["wlc_prepend"][0]
        prepended = RECIPES["wlc_prepend"][1]
        direct = (
            "*apfReceiveTask: Jul 14 15:41:24.640: %APF-6-USER_NAME_CREATED: "
            "[SS]apf_ms.c:9003 Username entry (3E-A8-8D-20-D1-1E) with length "
            "(17) created for mobile 3e:a8:8d:20:d1:1e"
        )
        op = _verify.evaluate_rule(rule, prepended)
        od = _verify.evaluate_rule(rule, direct)
        for out in (op, od):
            self.assertEqual(
                out.get("xdm.event.original_event_type"),
                "APF-6-USER_NAME_CREATED",
            )
            self.assertEqual(
                out.get("xdm.source.host.mac_addresses"),
                ["3e:a8:8d:20:d1:1e"],
            )
        # Host is sourced from the envelope, so only the prepended form has it.
        self.assertEqual(op.get("xdm.observer.name"), "wlc-mgmt.example.net")
        self.assertIsNone(od.get("xdm.observer.name"))

    def test_wlc_recipe_on_users_exact_line(self):
        # The exact line the user reported (a real Cisco WLC relay-prepend).
        rule = RECIPES["wlc_prepend"][0]
        line = (
            "<134>Jul 14 15:41:24 mo332-ha-mgmt.au.simon.net moe12-active: "
            "*haSSOServiceTask3: Jul 14 15:41:24.640: %APF-6-USER_NAME_CREATED: "
            "[SS]apf_ms.c:9003 Username entry (3E-A8-8D-20-D1-1E) with length "
            "(17) created for mobile 3e:a8:8d:20:d1:1e"
        )
        out = _verify.evaluate_rule(rule, line)
        self.assertEqual(out.get("xdm.observer.name"), "mo332-ha-mgmt.au.simon.net")
        self.assertEqual(
            out.get("xdm.event.original_event_type"), "APF-6-USER_NAME_CREATED"
        )
        self.assertEqual(
            out.get("xdm.source.host.mac_addresses"), ["3e:a8:8d:20:d1:1e"]
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
