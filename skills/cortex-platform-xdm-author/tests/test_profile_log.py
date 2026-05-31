# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Behavioural tests for ``scripts/profile_log.py``.

Mirrors the test_lint_rule.py shape: import the ``profile()`` function
directly for fast assertions, and shell out via ``subprocess`` to
exercise the CLI exit-code and output-format contract.

Headline fixture is ``acmeshield_waf.log`` (enhanced WAF telemetry
with object-arrays, header-pair arrays, optional fields, and null
values) -- the dataset the spec calls out as the accuracy-collapse
case for manual log analysis.
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
PROFILE_SCRIPT = bundle_root() / "scripts" / "profile_log.py"


def _load_module():
    """Import ``profile_log`` from the bundled script without making
    the script a permanent member of any package."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("profile_log", PROFILE_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


_pl = _load_module()
profile = _pl.profile
infer_type = _pl.infer_type


def _profile_fixture(name: str) -> dict:
    text = (FIXTURES / name).read_text(encoding="utf-8")
    return profile(str(FIXTURES / name), text)


# --------------------------------------------------------------------
# Headline fixture: enhanced AcmeShield WAF
# --------------------------------------------------------------------


class TestAcmeShieldWaf(unittest.TestCase):
    """The spec's accuracy-collapse case: nested object-arrays,
    header-pair arrays, a clear phase discriminator, and a
    deliberately-null optional field."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.ws = _profile_fixture("acmeshield_waf.log")
        cls.fields = {f["path"]: f for f in cls.ws["fields"]}

    def test_detected_format_is_json(self) -> None:
        self.assertEqual(self.ws["detected_format"], "json")

    def test_record_count_matches_sample(self) -> None:
        self.assertEqual(self.ws["record_count"], 2)

    def test_nested_array_path_surfaces(self) -> None:
        """``transactions[].http.method`` must be discoverable -- this
        is the central path the spec calls out as needing the profiler
        to recover."""
        self.assertIn("transactions[].http.method", self.fields)
        self.assertEqual(self.fields["transactions[].http.method"]["type"], "string")

    def test_transactions_array_discriminator_is_phase(self) -> None:
        """The ``transactions[]`` object-array must report its
        ``phase`` discriminator with values request and response so the
        agent knows to phase-filter the projection."""
        oa = next(
            (a for a in self.ws["object_arrays"] if a["path"] == "transactions[]"),
            None,
        )
        self.assertIsNotNone(oa, "no transactions[] entry in object_arrays")
        self.assertEqual(oa["discriminator"], "phase")
        self.assertEqual(sorted(oa["values"]), ["request", "response"])

    def test_session_user_id_null_rate_is_half(self) -> None:
        """``session.user_id`` is null in event 1 and present in
        event 2, so the recorded null rate must be 0.5."""
        f = self.fields.get("session.user_id")
        self.assertIsNotNone(f, "session.user_id not in field list")
        self.assertAlmostEqual(f["null_rate"], 0.5, places=2)

    def test_header_pair_array_surfaces_named_keys(self) -> None:
        """The ``{name, value}`` header arrays must surface each named
        header as its own synthetic field so the agent does not have
        to invent the routing -- the user-agent header in particular
        must be picked up because it carries a high-frequency XDM
        candidate (``xdm.source.user_agent``)."""
        path = "transactions[].http.headers[name=User-Agent]"
        f = self.fields.get(path)
        self.assertIsNotNone(f, f"{path} not in field list")
        self.assertEqual(f["leaf"], "User-Agent")
        # XDM candidate suggestion should land xdm.source.user_agent
        # near the top.
        suggested = [c["xdm_path"] for c in (f.get("xdm_candidates") or [])]
        self.assertIn(
            "xdm.source.user_agent",
            suggested,
            f"expected xdm.source.user_agent in candidates, got {suggested}",
        )

    def test_xdm_candidate_for_client_ip(self) -> None:
        """``network.client.ip`` is the canonical source-IPv4 sink and
        must surface ``xdm.source.ipv4`` as a top candidate."""
        f = self.fields["network.client.ip"]
        self.assertEqual(f["type"], "ip")
        top = [c["xdm_path"] for c in f["xdm_candidates"][:2]]
        self.assertIn("xdm.source.ipv4", top)

    def test_boolean_type_inference(self) -> None:
        """``action.intercepted`` and ``transactions[].http.body_truncated``
        are JSON booleans -- the type inference must report them as
        ``boolean``, not ``string``."""
        self.assertEqual(self.fields["action.intercepted"]["type"], "boolean")
        self.assertEqual(
            self.fields["transactions[].http.body_truncated"]["type"], "boolean"
        )

    def test_timestamp_type_inference(self) -> None:
        self.assertEqual(self.fields["timestamp"]["type"], "timestamp")


# --------------------------------------------------------------------
# CEF fixture
# --------------------------------------------------------------------


class TestCef(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ws = _profile_fixture("sample.cef")
        cls.fields = {f["path"]: f for f in cls.ws["fields"]}

    def test_detected_format_is_cef(self) -> None:
        self.assertEqual(self.ws["detected_format"], "cef")

    def test_cef_headers_surface(self) -> None:
        for required in (
            "cef_vendor",
            "cef_product",
            "cef_signature_id",
            "cef_severity",
        ):
            self.assertIn(required, self.fields, f"{required} missing from CEF profile")

    def test_extension_kv_fields_surface(self) -> None:
        # Standard CEF extension tokens -- src / dst / spt / dpt -- must
        # be picked up by the kv parser embedded in the CEF reader.
        for required in ("src", "dst", "spt", "dpt", "act", "suser"):
            self.assertIn(required, self.fields, f"{required} missing from CEF profile")

    def test_src_field_gets_xdm_candidate(self) -> None:
        cands = self.fields["src"]["xdm_candidates"]
        self.assertTrue(
            cands and cands[0]["xdm_path"] == "xdm.source.ipv4",
            f"expected xdm.source.ipv4 top, got {cands}",
        )


# --------------------------------------------------------------------
# Key=value fixture
# --------------------------------------------------------------------


class TestKv(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ws = _profile_fixture("sample.kv")
        cls.fields = {f["path"]: f for f in cls.ws["fields"]}

    def test_detected_format_is_kv(self) -> None:
        self.assertEqual(self.ws["detected_format"], "kv")

    def test_quoted_values_decoded(self) -> None:
        # ``user="alice@example.com"`` -- the quotes must be stripped.
        self.assertEqual(self.fields["user"]["sample"], "alice@example.com")

    def test_src_ip_gets_xdm_candidate(self) -> None:
        cands = self.fields["src_ip"]["xdm_candidates"]
        self.assertTrue(cands)
        self.assertEqual(cands[0]["xdm_path"], "xdm.source.ipv4")


# --------------------------------------------------------------------
# CLI contract -- mirrors test_lint_rule.py TestCliContract
# --------------------------------------------------------------------


class TestCliContract(unittest.TestCase):
    def _run(self, fixture: str, extra=()) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(PROFILE_SCRIPT), str(FIXTURES / fixture), *extra],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_clean_run_emits_json_worksheet(self) -> None:
        cp = self._run("acmeshield_waf.log")
        self.assertEqual(cp.returncode, 0, cp.stderr)
        parsed = json.loads(cp.stdout)
        self.assertEqual(parsed["detected_format"], "json")
        self.assertEqual(parsed["record_count"], 2)
        self.assertTrue(parsed["fields"], "fields array empty")
        self.assertTrue(parsed["object_arrays"], "object_arrays array empty")

    def test_text_format(self) -> None:
        cp = self._run("acmeshield_waf.log", ["--format", "text"])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("detected_format: json", cp.stdout)
        self.assertIn("transactions[]", cp.stdout)

    def test_missing_file_exits_two(self) -> None:
        cp = subprocess.run(
            [sys.executable, str(PROFILE_SCRIPT), "/nonexistent/sample.log"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(cp.returncode, 2)

    def test_no_argv_exits_one(self) -> None:
        cp = subprocess.run(
            [sys.executable, str(PROFILE_SCRIPT)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(cp.returncode, 1)


# --------------------------------------------------------------------
# Cleanup-pass regression coverage
# --------------------------------------------------------------------


class TestIntDiscriminator(unittest.TestCase):
    """An object-array discriminated by an integer field (HTTP status,
    severity level, etc.) must be detected and surfaced. The pre-cleanup
    detector had a dead int branch that silently filtered ints out."""

    def test_int_discriminator_is_detected_and_stringified(self) -> None:
        import json
        import tempfile

        payload = [
            {
                "requests": [
                    {"status": 200, "url": "/a"},
                    {"status": 302, "url": "/b"},
                ]
            },
            {
                "requests": [
                    {"status": 403, "url": "/c"},
                    {"status": 200, "url": "/d"},
                ]
            },
        ]
        with tempfile.NamedTemporaryFile(
            "w", suffix=".log", delete=False
        ) as tmp:
            tmp.write(json.dumps(payload))
            tmp_path = tmp.name
        try:
            with open(tmp_path, encoding="utf-8") as fh:
                ws = profile(tmp_path, fh.read())
        finally:
            Path(tmp_path).unlink(missing_ok=True)

        oa = next(
            (a for a in ws["object_arrays"] if a["path"] == "requests[]"),
            None,
        )
        self.assertIsNotNone(oa, "requests[] not in object_arrays")
        self.assertEqual(oa["discriminator"], "status")
        self.assertEqual(sorted(oa["values"]), ["200", "302", "403"])


class TestIpv6FalsePositives(unittest.TestCase):
    """MAC addresses and bare clock times must not be mis-tagged as ip.
    Real IPv4s and IPv6s must still be typed as ip."""

    def test_mac_is_string_not_ip(self) -> None:
        self.assertEqual(infer_type("aa:bb:cc:dd:ee:ff"), "string")

    def test_clock_time_is_string_not_ip(self) -> None:
        self.assertEqual(infer_type("12:34:56"), "string")
        self.assertEqual(infer_type("09:00"), "string")
        self.assertEqual(infer_type("23:59:59.123"), "string")

    def test_ipv4_still_typed_as_ip(self) -> None:
        self.assertEqual(infer_type("191.96.12.44"), "ip")

    def test_real_ipv6_is_typed_as_ip(self) -> None:
        # Spot a few canonical IPv6 forms.
        self.assertEqual(infer_type("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), "ip")
        self.assertEqual(infer_type("fe80::1"), "ip")
        self.assertEqual(infer_type("::1"), "ip")

    def test_acmeshield_client_ip_still_ip(self) -> None:
        """Smoke guard: the headline AcmeShield fixture's
        ``network.client.ip`` must still type as ip after the
        tightening."""
        ws = _profile_fixture("acmeshield_waf.log")
        fields = {f["path"]: f for f in ws["fields"]}
        self.assertEqual(fields["network.client.ip"]["type"], "ip")


if __name__ == "__main__":
    unittest.main()
