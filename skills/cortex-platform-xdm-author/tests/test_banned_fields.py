# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Guards for the banned-field mechanism (assets/banned_fields.json, lint
ERR-029, references/banned-fields.md).

A banned field is a real Cortex XDM path that must never be assigned in a
MODEL rule because it belongs to an internal / non-event data model
(Cortex rejects it with 'not part of the selected data model'). These
tests keep the mechanism honest:

  1. Registry shape: banned_fields.json parses, every entry carries a
     path, a reason and an alternative, and no entry duplicates another.
  2. Schema exclusion: no banned path appears in references/xdm-schema.md
     (the schema lists only fields a MODEL rule may assign).
  3. Doc sync: the table in references/banned-fields.md lists exactly the
     registry entries, so the human view never drifts from the machine
     view.
  4. Regression guard: no reference file, worked example, SKILL.md or the
     MAPPED-header template contains an ASSIGNMENT to a banned path. A
     prose mention (a "never do this" warning) is fine; a code line that
     assigns the field is a regression. This guard covers every future
     registry entry automatically.
  5. Linter behaviour: the ERR-029 fixture fires ERR-029 and does NOT
     also fire ERR-020 (the ban message must win over "invented path").
"""

from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _helpers import bundle_root, read_json, read_text  # noqa: E402


def _registry():
    return read_json("assets/banned_fields.json")


def _banned_paths():
    return [e["path"] for e in _registry().get("banned", [])]


def _lint(fixture_name: str):
    """Run the bundled linter in-process on a fixture; return rule ids."""
    lint_path = bundle_root() / "scripts" / "lint_rule.py"
    spec = importlib.util.spec_from_file_location("lint_rule", lint_path)
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(lint_path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    source = (bundle_root() / "tests" / "fixtures" / fixture_name).read_text(
        encoding="utf-8"
    )
    return [v["rule_id"] for v in module.lint(source)]


class TestRegistryShape(unittest.TestCase):
    def test_entries_complete_and_unique(self):
        entries = _registry().get("banned", [])
        self.assertTrue(entries, "banned_fields.json has no entries")
        seen = set()
        for e in entries:
            with self.subTest(path=e.get("path")):
                self.assertTrue(e.get("path"), "entry missing path")
                self.assertTrue(
                    e.get("reason"), f"{e.get('path')}: entry missing reason"
                )
                self.assertTrue(
                    e.get("alternative"),
                    f"{e.get('path')}: entry missing alternative",
                )
                self.assertNotIn(e["path"], seen, f"duplicate: {e['path']}")
                seen.add(e["path"])

    def test_paths_look_like_xdm_leaves(self):
        for path in _banned_paths():
            with self.subTest(path=path):
                self.assertRegex(path, r"^xdm\.[a-z0-9_.]+$")


class TestSchemaExclusion(unittest.TestCase):
    def test_banned_paths_absent_from_schema(self):
        schema = read_text("references/xdm-schema.md")
        for path in _banned_paths():
            with self.subTest(path=path):
                self.assertNotIn(
                    f"{path} --",
                    schema,
                    f"{path} is banned but still listed in xdm-schema.md",
                )


class TestDocSync(unittest.TestCase):
    def test_banned_fields_md_matches_registry(self):
        doc = read_text("references/banned-fields.md")
        doc_paths = set(re.findall(r"^\| `(xdm\.[a-z0-9_.]+)` \|", doc, re.M))
        self.assertEqual(
            doc_paths,
            set(_banned_paths()),
            "references/banned-fields.md table out of sync with "
            "assets/banned_fields.json",
        )


class TestNoBannedAssignmentsInDocs(unittest.TestCase):
    """No shipped reference, worked example, SKILL.md or the header
    template may ASSIGN a banned field. This is the guard that stops a
    banned field creeping back into recommended content."""

    def _assignment_re(self):
        alts = "|".join(re.escape(p) for p in _banned_paths())
        return re.compile(rf"^\s*(?:{alts})\s*=(?!=)", re.M)

    def test_no_assignments(self):
        root = bundle_root()
        scan = [root / "SKILL.md", root / "assets" / "modeling_header_template.xql"]
        scan += sorted((root / "references").rglob("*.md"))
        pattern = self._assignment_re()
        offenders = []
        for p in scan:
            text = p.read_text(encoding="utf-8")
            for m in pattern.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                offenders.append(f"{p.relative_to(root)}:{line_no}")
        self.assertFalse(
            offenders,
            "banned field assigned in shipped content: " + ", ".join(offenders),
        )


class TestLinterBehaviour(unittest.TestCase):
    def test_err029_fires_and_err020_stays_silent(self):
        ids = _lint("err029_banned_cloud_source_type.xql")
        self.assertIn("ERR-029", ids)
        self.assertNotIn(
            "ERR-020",
            ids,
            "banned path must yield the precise ERR-029 ban message, "
            "not the generic invented-path error",
        )


if __name__ == "__main__":
    unittest.main()
