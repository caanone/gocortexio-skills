# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Substring guards on the MAPPED-header template.

The MAPPED-header is mandatory on every rule the skill emits, and the
template at ``assets/modeling_header_template.xql`` is the shape every
agent will follow. If a required section is renamed or removed from the
template, every downstream rule loses the same section in lock-step, so
this test guards the template's required rows.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Make ``_helpers`` importable regardless of unittest invocation form.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _helpers import read_text  # noqa: E402


# Required substrings that MUST appear somewhere in the template.
# Loose substring match by design: section labels are stable enough to
# pin, but exact-line matching would fail on cosmetic edits (spacing,
# punctuation) without protecting anything substantive.
REQUIRED_SUBSTRINGS = [
    # Vendor / product / dataset identification
    "<Vendor>",
    "<Product>",
    "<vendor>_<product>_raw",
    # Description rubric
    "One-paragraph description",
    # Field-mapping section
    "ALERT / EVENT FIELD MAPPING",
    # NOT MAPPED rubric -- sink for fields deliberately not mapped
    "NOT MAPPED",
    # Observer rubric -- every MODEL rule must set vendor + product
    "xdm.observer.vendor",
    "xdm.observer.product",
    # Event classification rubric
    "xdm.event.type",
    # MODEL header line -- the rule's actual XQL opener
    "[MODEL: dataset=<vendor>_<product>_raw]",
    # SPDX licence line
    "SPDX-License-Identifier: AGPL-3.0-or-later",
    # GoCortexIO attribution
    "GoCortexIO",
]


class TestHeaderTemplate(unittest.TestCase):
    """Required substrings in assets/modeling_header_template.xql."""

    @classmethod
    def setUpClass(cls):
        cls.text = read_text("assets/modeling_header_template.xql")

    def test_required_substrings_present(self):
        for needle in REQUIRED_SUBSTRINGS:
            with self.subTest(substring=needle):
                self.assertIn(
                    needle,
                    self.text,
                    f"MAPPED-header template missing required substring: '{needle}'",
                )

    def test_starts_with_comment_block(self):
        # Mapped header begins as // comments -- the [MODEL: ...] line
        # appears later. Guards against a rewrite that drops the header
        # entirely.
        first_nonempty = next(
            (ln for ln in self.text.splitlines() if ln.strip()),
            "",
        )
        self.assertTrue(
            first_nonempty.startswith("//"),
            f"template should begin with a comment line; got: {first_nonempty!r}",
        )

    def test_ends_with_semicolon(self):
        # The XQL rule terminator. A template that doesn't end ; would
        # produce non-compiling rules.
        stripped = self.text.rstrip()
        self.assertTrue(
            stripped.endswith(";"),
            f"template must end with ';'; last 40 chars: {stripped[-40:]!r}",
        )

    def test_model_header_line_no_leading_pipe(self):
        # The first stage after [MODEL: ...] is `filter`, NOT `| filter`.
        # WARN-017 fires on a leading pipe. The template demonstrates
        # the correct shape.
        lines = self.text.splitlines()
        try:
            model_idx = next(i for i, ln in enumerate(lines) if ln.startswith("[MODEL:"))
        except StopIteration:
            self.fail("template has no [MODEL: ...] header line")
        # Find the next non-blank, non-comment line after [MODEL: ...].
        for ln in lines[model_idx + 1 :]:
            stripped = ln.strip()
            if not stripped or stripped.startswith("//"):
                continue
            self.assertFalse(
                stripped.startswith("|"),
                f"first stage after [MODEL:] must not have a leading pipe "
                f"(WARN-017); got: {stripped!r}",
            )
            break


if __name__ == "__main__":
    unittest.main()
