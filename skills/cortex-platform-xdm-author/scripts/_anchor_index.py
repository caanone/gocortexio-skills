# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: GoCortexIO
"""Shared field-anchor index helpers.

Both ``lookup_anchor.py`` and ``profile_log.py`` import these helpers
so the corpus logic lives in one place.

Public surface:

    ANCHORS_PATH         absolute path to the shipped JSON
    normalise_synonym    str -> str
    load_anchors         () -> dict (exits 2 on failure)
    build_reverse_index  dict -> dict   (synonym -> ranked xdm.* candidates)
    forward_synonyms     (dict, xdm_path) -> ranked vendor synonyms
    related_fields       (xdm_path) -> companion / mirror partners

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
    """Normalise a vendor field name to its canonical anchor key. Lower-
    case, strip a leading ``@``, collapse punctuation to underscore,
    strip a leading underscore, strip a leading ``tmp_`` prefix, then
    collapse and trim trailing underscores. The field-anchor index is
    keyed by this normalised form, so the same transform must run on
    every lookup input.
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


def forward_synonyms(data: dict, xdm_path: str) -> list:
    """Vendor synonyms historically mapped to ``xdm_path``, ranked by
    descending per-synonym count. Drives the ``--reverse`` lookup: given
    an XDM target, what raw column names tend to fill it."""
    entry = (data.get("anchors") or {}).get(xdm_path)
    if not entry:
        return []
    syns = sorted(
        (entry.get("synonyms") or []),
        key=lambda s: s.get("count", 0),
        reverse=True,
    )
    return [
        {"synonym": s.get("synonym"), "count": s.get("count", 0)}
        for s in syns
        if s.get("synonym")
    ]


# Companion / mirror field groups (transformation-patterns.md). Every
# member of a group lists the others as related: when you map one, the
# others are usually mapped together. Expanded into a symmetric lookup
# below.
_RELATED_GROUPS = [
    ["xdm.source.ipv4", "xdm.target.ipv4"],
    ["xdm.source.ipv4", "xdm.source.host.ipv4_addresses"],
    ["xdm.target.ipv4", "xdm.target.host.ipv4_addresses"],
    ["xdm.source.host.ipv4_addresses", "xdm.target.host.ipv4_addresses"],
    ["xdm.source.user.username", "xdm.source.user.upn"],
    ["xdm.target.user.username", "xdm.target.user.upn"],
    ["xdm.source.user.username", "xdm.target.user.username"],
    ["xdm.source.user.username", "xdm.source.user.identifier"],
    ["xdm.source.host.hostname", "xdm.source.host.fqdn"],
    ["xdm.target.host.hostname", "xdm.target.host.fqdn"],
    ["xdm.source.host.hostname", "xdm.target.host.hostname"],
    ["xdm.event.outcome", "xdm.observer.action"],
    ["xdm.event.log_level", "xdm.alert.severity"],
    ["xdm.event.type", "xdm.event.original_event_type"],
    ["xdm.alert.name", "xdm.alert.original_threat_name"],
    ["xdm.event.id", "xdm.alert.original_alert_id"],
    ["xdm.alert.category", "xdm.alert.subcategory"],
    ["xdm.alert.mitre_tactics", "xdm.alert.mitre_techniques"],
    ["xdm.source.is_internal_ip", "xdm.target.is_internal_ip"],
]


def related_fields(xdm_path: str) -> list:
    """Companion / mirror fields for ``xdm_path``: the partners you
    normally map alongside it. Deterministic, deduplicated, sorted."""
    out: set = set()
    for group in _RELATED_GROUPS:
        if xdm_path in group:
            out.update(g for g in group if g != xdm_path)
    return sorted(out)


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
