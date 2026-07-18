# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Floor guards for the endpoint const enums.

Endpoint telemetry (process / file / registry / image, from Sysmon, Windows
and Linux) needs the COMPLETE const enums, not the handful a build sample
shows. These tests assert xdm-const.md enumerates enough of each group and
that representative members resolve to the right group via the shared loader.
They are floor guards (>=) for the open-ended groups, so a later authoritative
addition does not break the suite, and exact counts for the small closed sets.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

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


class TestEndpointConstEnums(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.consts = _schema.load_xdm_consts()

    def _group(self, name):
        return self.consts.get(name, set())

    def test_operation_type_complete(self):
        # 56 authoritative members; floor guard tolerates future additions.
        self.assertGreaterEqual(len(self._group("OPERATION_TYPE")), 56)

    def test_operation_type_has_endpoint_verbs(self):
        for verb in (
            "OPERATION_TYPE_PROCESS_CREATE",
            "OPERATION_TYPE_PROCESS_TERMINATE",
            "OPERATION_TYPE_EXECUTION",
            "OPERATION_TYPE_IMAGE_LOAD",
            "OPERATION_TYPE_FILE_REMOVE",
            "OPERATION_TYPE_REGISTRY_SET_VALUE",
            "OPERATION_TYPE_REGISTRY_DELETE_KEY",
        ):
            self.assertIn(f"XDM_CONST.{verb}", self._group("OPERATION_TYPE"))

    def test_signature_status_closed_set(self):
        self.assertEqual(len(self._group("SIGNATURE_STATUS")), 4)

    def test_registry_value_type_closed_set(self):
        self.assertEqual(len(self._group("REGISTRY_VALUE_TYPE")), 11)

    def test_os_family_covers_endpoint_platforms(self):
        self.assertGreaterEqual(len(self._group("OS_FAMILY")), 12)
        for fam in ("OS_FAMILY_WINDOWS", "OS_FAMILY_LINUX", "OS_FAMILY_MACOS"):
            self.assertIn(f"XDM_CONST.{fam}", self._group("OS_FAMILY"))

    def test_members_resolve_to_expected_group(self):
        cases = {
            "XDM_CONST.OPERATION_TYPE_REGISTRY_SET_VALUE": "OPERATION_TYPE",
            "XDM_CONST.REGISTRY_VALUE_TYPE_REG_SZ": "REGISTRY_VALUE_TYPE",
            "XDM_CONST.SIGNATURE_STATUS_UNSIGNED": "SIGNATURE_STATUS",
            "XDM_CONST.OS_FAMILY_UBUNTU": "OS_FAMILY",
        }
        for member, group in cases.items():
            self.assertEqual(_schema.const_group_for(member), group, member)

    def test_no_ungrouped_leakage(self):
        # Every enumerated member buckets into a real schema group.
        self.assertEqual(self.consts.get("_UNGROUPED", set()), set())


if __name__ == "__main__":
    unittest.main()
