# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: GoCortexIO
"""Shared XDM schema + XDM_CONST loaders.

Parses the bundle's own reference markdown into memory so the linter and
the authoring tools share one source of truth. No separate data file is
shipped: ``references/xdm-schema.md`` and ``references/xdm-const.md`` ARE
the schema, and the doc-consistency test already guards their contents.

Public surface:

    SCHEMA_PATH          absolute path to references/xdm-schema.md
    CONST_PATH           absolute path to references/xdm-const.md
    load_xdm_paths       () -> dict {path: {type, is_array, const_group}}
    load_xdm_consts      () -> dict {group: set(full XDM_CONST.* members)}
    xdm_path_exists      (path) -> bool
    xdm_path_is_array    (path) -> bool
    const_group_for      (const) -> Optional[str]
    all_consts           () -> set(full XDM_CONST.* members)

Python 3.9+ stdlib only.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Dict, Iterator, Optional, Set, Tuple


SELF_DIR = Path(__file__).resolve().parent
REFERENCES_DIR = SELF_DIR.parent / "references"
SCHEMA_PATH = REFERENCES_DIR / "xdm-schema.md"
CONST_PATH = REFERENCES_DIR / "xdm-const.md"
# The full ATT&CK constant enum is large, so it ships as a machine-readable
# asset rather than being enumerated line-by-line in xdm-const.md. The const
# loader merges it so every documented MITRE constant still validates.
MITRE_CROSSWALK_PATH = SELF_DIR.parent / "assets" / "mitre_crosswalk.json"

# A schema line is ``  xdm.foo.bar -- TYPE`` with an optional ``(Array)``
# suffix. The double-dash separator matches the ASCII convention used
# throughout the bundle.
_SCHEMA_LINE_RE = re.compile(
    r"^\s*(xdm\.[a-z0-9_.]+)\s+--\s+(.+?)\s*$"
)
_ARRAY_SUFFIX_RE = re.compile(r"\s*\(Array\)\s*$")
# A bare ``XDM_CONST.NAME`` token, optionally followed by a parenthesised
# annotation such as ``(200)`` in the HTTP response-code list.
_CONST_LINE_RE = re.compile(r"^\s*(XDM_CONST\.[A-Z][A-Z0-9_]*)\b")

# Fields the schema does not mark ``(Array)`` but which Cortex still
# requires to be built with ``arraycreate()``. Documented in the
# "Important notes" section of references/xdm-schema.md.
_FORCED_ARRAY_PATHS = {
    "xdm.email.recipients",
}

_paths_cache: Optional[Dict[str, dict]] = None
_consts_cache: Optional[Dict[str, Set[str]]] = None
_const_group_cache: Optional[Dict[str, str]] = None


def _read(path: Path) -> str:
    if not path.is_file():
        sys.stderr.write(
            f"error: reference file not found at {path}\n"
            "Reinstall the skill bundle to restore the references.\n"
        )
        sys.exit(2)
    return path.read_text(encoding="utf-8")


def load_xdm_paths() -> Dict[str, dict]:
    """Return ``{path: {"type": str, "is_array": bool,
    "const_group": Optional[str]}}`` parsed from xdm-schema.md.

    ``type`` is the base type with any ``(Array)`` suffix removed.
    ``const_group`` is the group name (without the ``XDM_CONST.`` prefix)
    when the field is XDM_CONST-typed, else None.
    """
    global _paths_cache
    if _paths_cache is not None:
        return _paths_cache

    out: Dict[str, dict] = {}
    in_fence = False
    for line in _read(SCHEMA_PATH).splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            continue
        m = _SCHEMA_LINE_RE.match(line)
        if not m:
            continue
        path = m.group(1)
        raw_type = m.group(2)
        is_array = bool(_ARRAY_SUFFIX_RE.search(raw_type)) or path in _FORCED_ARRAY_PATHS
        base_type = _ARRAY_SUFFIX_RE.sub("", raw_type).strip()
        const_group = None
        if base_type.startswith("XDM_CONST."):
            const_group = base_type[len("XDM_CONST."):]
        out[path] = {
            "type": base_type,
            "is_array": is_array,
            "const_group": const_group,
        }
    _paths_cache = out
    return out


def _schema_const_groups() -> Set[str]:
    """Group names declared as XDM_CONST types in the schema, e.g.
    ``OUTCOME``, ``HTTP_RSP_CODE``, ``MITRE_TECHNIQUE``. Used to bucket
    the flat constant list in xdm-const.md by longest-prefix match."""
    groups = set()
    for meta in load_xdm_paths().values():
        if meta["const_group"]:
            groups.add(meta["const_group"])
    return groups


def _mitre_crosswalk_consts() -> Iterator[Tuple[str, str]]:
    """Yield ``(full XDM_CONST member, group)`` for every MITRE technique /
    tactic constant in the shipped crosswalk asset. Silent no-op if the
    asset is absent or unreadable."""
    try:
        data = json.loads(MITRE_CROSSWALK_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    for suffix in (data.get("techniques") or {}).values():
        yield f"XDM_CONST.{suffix}", "MITRE_TECHNIQUE"
    for suffix in (data.get("tactics") or {}).values():
        yield f"XDM_CONST.{suffix}", "MITRE_TACTIC"


def load_xdm_consts() -> Dict[str, Set[str]]:
    """Return ``{group: set(full "XDM_CONST.*" members)}`` parsed from
    xdm-const.md. Each member is bucketed into the longest schema group
    name that prefixes it (on an underscore boundary). Members with no
    matching schema group fall under the key ``"_UNGROUPED"``.
    """
    global _consts_cache, _const_group_cache
    if _consts_cache is not None:
        return _consts_cache

    members: Set[str] = set()
    in_fence = False
    for line in _read(CONST_PATH).splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            continue
        m = _CONST_LINE_RE.match(line)
        if m:
            members.add(m.group(1))

    groups = sorted(_schema_const_groups(), key=len, reverse=True)
    by_group: Dict[str, Set[str]] = {}
    member_to_group: Dict[str, str] = {}
    for member in members:
        tail = member[len("XDM_CONST."):]
        assigned = "_UNGROUPED"
        for g in groups:
            if tail == g or tail.startswith(g + "_"):
                assigned = g
                break
        by_group.setdefault(assigned, set()).add(member)
        member_to_group[member] = assigned

    # Merge the authoritative MITRE crosswalk: the full ATT&CK enum lives in
    # the asset, so any documented technique / tactic constant validates.
    for member, grp in _mitre_crosswalk_consts():
        by_group.setdefault(grp, set()).add(member)
        member_to_group.setdefault(member, grp)

    _consts_cache = by_group
    _const_group_cache = member_to_group
    return by_group


def all_consts() -> Set[str]:
    """Flat set of every ``XDM_CONST.*`` member documented in the bundle."""
    out: Set[str] = set()
    for members in load_xdm_consts().values():
        out |= members
    return out


def const_group_for(const: str) -> Optional[str]:
    """Return the group name for a full ``XDM_CONST.*`` token, or None if
    the constant is not documented in the bundle."""
    load_xdm_consts()  # populates _const_group_cache
    assert _const_group_cache is not None
    return _const_group_cache.get(const)


def xdm_path_exists(path: str) -> bool:
    """True if ``path`` is a leaf field in the schema. Container prefixes
    (e.g. ``xdm.source`` when only ``xdm.source.ipv4`` is a leaf) are
    NOT considered existing leaves."""
    return path in load_xdm_paths()


def xdm_path_is_array(path: str) -> bool:
    """True if ``path`` is an Array-typed (or arraycreate-required) field."""
    meta = load_xdm_paths().get(path)
    return bool(meta and meta["is_array"])
