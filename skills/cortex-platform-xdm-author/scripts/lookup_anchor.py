#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: GoCortexIO
"""lookup_anchor.py <vendor_field_name> [vendor_field_name ...]

Look up vendor field names in the shipped field-anchor synonym index
(``assets/field_anchors.json``) and return the ranked ``xdm.*`` paths
historical rules mapped them to. JSON on stdout; one block per input.

Each result block:

    {
      "input": "<as-given>",
      "normalised": "<after normalisation>",
      "candidates": [
        { "xdm_path": "...", "frequency": int, "score": int,
          "synonym_count": int, "exampleVendors": [...] },
        ...
      ]
    }

Exit codes:
    0   success (even with no candidates found)
    1   argument error
    2   cannot locate or parse the anchor file

Python 3.9+ stdlib only.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Shared helpers live in _anchor_index.py. Re-export them here so
# importers that already write ``from lookup_anchor import X`` keep
# working.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _anchor_index import (  # noqa: E402
    ANCHORS_PATH,
    build_reverse_index,
    load_anchors,
    normalise_synonym,
)

__all__ = [
    "ANCHORS_PATH",
    "build_reverse_index",
    "load_anchors",
    "main",
    "normalise_synonym",
]


def main(argv: list) -> int:
    args = argv[1:]
    if not args:
        sys.stderr.write(
            "usage: python3 lookup_anchor.py <vendor_field_name> "
            "[vendor_field_name ...]\n"
        )
        return 1

    data = load_anchors()
    reverse = build_reverse_index(data)

    results = []
    for inp in args:
        normalised = normalise_synonym(inp)
        candidates = reverse.get(normalised, [])
        results.append(
            {
                "input": inp,
                "normalised": normalised,
                "candidates": candidates,
            }
        )

    sys.stdout.write(json.dumps(results, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
