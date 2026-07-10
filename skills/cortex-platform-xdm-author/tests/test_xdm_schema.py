# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for ``scripts/_xdm_schema.py``.

The loader parses the bundle's own reference markdown into the schema
and constant tables that the linter and the authoring tools depend on.
These tests pin the parse so a reference edit that breaks the shape is
caught here rather than surfacing as a mis-fire deep in the linter.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import _xdm_schema as x  # noqa: E402


class TestPathLoader(unittest.TestCase):
    def setUp(self):
        self.paths = x.load_xdm_paths()

    def test_substantial_path_count(self):
        self.assertGreater(len(self.paths), 400)

    def test_known_scalar_path(self):
        meta = self.paths.get("xdm.source.ipv4")
        self.assertIsNotNone(meta)
        self.assertFalse(meta["is_array"])

    def test_array_suffix_parsed(self):
        meta = self.paths.get("xdm.source.host.ipv4_addresses")
        self.assertIsNotNone(meta)
        self.assertEqual(meta["type"], "IPv4")
        self.assertTrue(meta["is_array"])

    def test_const_typed_field(self):
        meta = self.paths.get("xdm.event.outcome")
        self.assertIsNotNone(meta)
        self.assertEqual(meta["const_group"], "OUTCOME")

    def test_const_array_field(self):
        meta = self.paths.get("xdm.event.tags")
        self.assertIsNotNone(meta)
        self.assertTrue(meta["is_array"])
        self.assertEqual(meta["const_group"], "EVENT_TAG")

    def test_forced_array_recipients(self):
        # Not labelled (Array) in the schema, but Cortex requires
        # arraycreate(); the loader forces the flag.
        self.assertTrue(x.xdm_path_is_array("xdm.email.recipients"))

    def test_leaf_array_dataclass_fields(self):
        # Regression: these leaf fields are Datatype String/const but
        # Dataclass Array in the authoritative schema. A scalar assignment
        # is rejected by the tenant (Expected array but received string),
        # so the schema must mark them (Array) for WARN-035 to catch it.
        for path in (
            "xdm.alert.risks",
            "xdm.alert.mitre_tactics",
            "xdm.alert.mitre_techniques",
            "xdm.database.tables",
            "xdm.email.bcc",
            "xdm.email.cc",
            "xdm.logon.assigned_rights",
            "xdm.network.protocol_layers",
        ):
            self.assertTrue(
                x.xdm_path_is_array(path), f"{path} must be Array-typed"
            )

    def test_path_existence_helpers(self):
        self.assertTrue(x.xdm_path_exists("xdm.source.ipv4"))
        self.assertFalse(x.xdm_path_exists("xdm.event.start_time"))
        self.assertFalse(x.xdm_path_exists("xdm.totally.invented.path"))


class TestConstLoader(unittest.TestCase):
    def setUp(self):
        self.groups = x.load_xdm_consts()

    def test_outcome_group_complete(self):
        self.assertEqual(
            self.groups.get("OUTCOME"),
            {
                "XDM_CONST.OUTCOME_SUCCESS",
                "XDM_CONST.OUTCOME_FAILED",
                "XDM_CONST.OUTCOME_PARTIAL",
                "XDM_CONST.OUTCOME_UNKNOWN",
            },
        )

    def test_every_const_buckets_to_a_schema_group(self):
        # No documented constant should fall outside a real schema group.
        self.assertEqual(self.groups.get("_UNGROUPED", set()), set())

    def test_group_lookup(self):
        self.assertEqual(
            x.const_group_for("XDM_CONST.HTTP_RSP_CODE_OK"), "HTTP_RSP_CODE"
        )
        self.assertEqual(
            x.const_group_for("XDM_CONST.MITRE_TECHNIQUE_VALID_ACCOUNTS"),
            "MITRE_TECHNIQUE",
        )

    def test_unknown_const_returns_none(self):
        self.assertIsNone(x.const_group_for("XDM_CONST.NOT_A_REAL_CONST"))

    def test_all_consts_substantial(self):
        self.assertGreater(len(x.all_consts()), 150)


if __name__ == "__main__":
    unittest.main()
