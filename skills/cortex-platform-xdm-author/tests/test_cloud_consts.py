# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Guards for the cloud const enums.

CLOUD_PROVIDER and AGENT_TYPE are small closed enums completed from the
authoritative schema. CLOUD_SERVICE_TYPE is deliberately NOT enumerated (a
huge, fast-moving per-service enum with no complete authoritative source), so
this test also pins that it stays out of the const list -- the OMIT-and-fallback
contract the cloud mapping relies on.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _helpers import bundle_root  # noqa: E402

SCRIPTS = bundle_root() / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


_schema = _load("_xdm_schema")


class TestCloudConstEnums(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.consts = _schema.load_xdm_consts()

    def test_cloud_provider_complete(self):
        p = self.consts.get("CLOUD_PROVIDER", set())
        self.assertEqual(len(p), 5)
        for m in ("AWS", "AZURE", "GCP", "ALIBABA", "ON_PREM"):
            self.assertIn(f"XDM_CONST.CLOUD_PROVIDER_{m}", p)

    def test_agent_type_complete(self):
        a = self.consts.get("AGENT_TYPE", set())
        self.assertEqual(len(a), 4)
        for m in ("REGULAR", "CLOUD", "COLLECTOR", "VDI"):
            self.assertIn(f"XDM_CONST.AGENT_TYPE_{m}", a)

    def test_cloud_service_type_not_enumerated(self):
        # Intentionally OMIT-and-fallback: do not enumerate the huge, uncurated
        # per-service enum. A stray CLOUD_SERVICE_TYPE_* member creeping into
        # xdm-const.md would falsely imply the closed set is known.
        self.assertEqual(self.consts.get("CLOUD_SERVICE_TYPE", set()), set())

    def test_no_ungrouped_leakage(self):
        self.assertEqual(self.consts.get("_UNGROUPED", set()), set())


if __name__ == "__main__":
    unittest.main()
