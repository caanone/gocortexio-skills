# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Standing mapping-accuracy guard.

Runs the author-curated corpus (tests/corpus/mapping_matrix.json) through
scripts/score_mappings.py: every worked-example rule must reproduce the CORRECT
XDM output field-for-field on every sample. A mapping regression drops the score
and fails here. The corpus ground truth is authored from provider docs + the XDM
schema, NOT from any content pack -- this pins the skill's output to correct, not
to whatever a pack happens to emit.
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


_score = _load("score_mappings")


class TestMappingAccuracy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = _score.load_corpus()

    def test_corpus_is_substantial(self):
        cases = self.corpus.get("cases", [])
        self.assertGreaterEqual(len(cases), 10)
        sources = {c.get("source") for c in cases}
        for provider in ("aws_cloudtrail", "microsoft_azure", "gcp_cloud_audit"):
            self.assertIn(provider, sources)

    def test_full_field_for_field_accuracy(self):
        mismatches, totals = _score.score(self.corpus)
        detail = "; ".join(
            f"[{m['case']}] {m['path']}: want {m['want']!r} got {m['got']!r}"
            for m in mismatches
        )
        self.assertEqual(mismatches, [], f"mapping regressions: {detail}")
        # every case contributed at least one asserted field
        total = sum(t for _, t in totals.values())
        self.assertGreater(total, 0)

    def test_harness_detects_drift(self):
        # A deliberately wrong expectation must be caught -- proves the guard
        # actually compares values rather than passing vacuously.
        broken = {
            "cases": [{
                "name": "sanity-broken",
                "source": "aws_cloudtrail",
                "worked_example": "13-aws-cloudtrail-multi-event.md",
                "sample": {"eventName": "RunInstances", "eventSource": "ec2.amazonaws.com"},
                "expect": {"xdm.event.operation": "XDM_CONST.OPERATION_TYPE_DELETE"},
            }]
        }
        mismatches, _ = _score.score(broken)
        self.assertEqual(len(mismatches), 1)


if __name__ == "__main__":
    unittest.main()
