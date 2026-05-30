# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: GoCortexIO
"""Shared field-anchor index helpers.

Both ``lookup_anchor.py`` and ``profile_log.py`` import these helpers
so the corpus logic lives in one place.

Public surface:

    ANCHORS_PATH         absolute path to the shipped JSON
    normalise_synonym    str -> str
    load_anchors         () -> dict (exits 2 on failure)
    build_reverse_index  dict -> dict

Python 3.9+ stdlib only.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


SELF_DIR = Path(__file__).resolve().parent
ANCHORS_PATH = SELF_DIR.parent / "assets" / "field_anchors.json"

_PUNCT_RE = re.compile(r"[.\s\-]+")
_LEADING_UNDERSCORE_RE = re.compile(r"^_+")
_COLLAPSE_UNDERSCORE_RE = re.compile(r"_+")
_TRAILING_UNDERSCORE_RE = re.compile(r"_+$")


def normalise_synonym(raw: object) -> str:
    """Mirror of ``normaliseSynonym()`` in the upstream extractor that
    derives the field-anchor table. Lower-case, strip leading ``@``,
    collapse punctuation to underscore, strip leading underscore,
    strip a leading ``tmp_`` prefix, then collapse and trim trailing
    underscores.
    """
    s = "" if raw is None else str(raw)
    s = s.strip().lower()
    if s.startswith("@"):
        s = s[1:]
    s = _PUNCT_RE.sub("_", s)
    s = _LEADING_UNDERSCORE_RE.sub("", s)
    if s.startswith("tmp_"):
        s = s[4:]
    s = _COLLAPSE_UNDERSCORE_RE.sub("_", s)
    s = _TRAILING_UNDERSCORE_RE.sub("", s)
    return s


def load_anchors() -> dict:
    """Read and JSON-parse ``assets/field_anchors.json``. Exits 2 with
    a message on stderr if the file is missing or malformed.
    """
    if not ANCHORS_PATH.is_file():
        sys.stderr.write(
            f"error: field_anchors.json not found at {ANCHORS_PATH}\n"
            "Reinstall the skill bundle to restore "
            "assets/field_anchors.json.\n"
        )
        sys.exit(2)
    try:
        return json.loads(ANCHORS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"error: failed to parse {ANCHORS_PATH}: {exc}\n")
        sys.exit(2)


def build_reverse_index(data: dict) -> dict:
    """Build the inverted index: normalised synonym -> ranked candidate
    list. Score is per-synonym count times overall anchor frequency, so
    a field that one vendor uses heavily for an unusual XDM target does
    not outrank a widely-shared mapping.
    """
    reverse: dict = {}
    for xdm_path, entry in (data.get("anchors") or {}).items():
        frequency = entry.get("frequency", 0)
        example_vendors = entry.get("exampleVendors") or []
        for syn in entry.get("synonyms") or []:
            key = normalise_synonym(syn.get("synonym"))
            if not key:
                continue
            count = syn.get("count", 0)
            reverse.setdefault(key, []).append(
                {
                    "xdm_path": xdm_path,
                    "frequency": frequency,
                    "synonym_count": count,
                    "score": count * frequency,
                    "exampleVendors": example_vendors,
                }
            )
    for lst in reverse.values():
        lst.sort(key=lambda c: c["score"], reverse=True)
    return reverse
