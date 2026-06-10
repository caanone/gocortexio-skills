#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: GoCortexIO
"""mitre_map.py --kind technique --ids T1078,T1059 [--array] [--temp _ids]
   mitre_map.py --kind tactic --names "Credential Access,Execution"

Map MITRE technique / tactic IDs or names to the XDM_CONST.MITRE_*
constants and emit the assignment. The XDM constants use the canonical
ATT&CK NAME, not the T-id, so this resolves the mapping for you. Every
emitted constant is validated against the bundle's documented MITRE
lists (references/xdm-const.md); an ID or name that does not resolve is
reported and OMITTED, never invented.

--ids   input is ATT&CK IDs (T#### / TA####), resolved via a curated
        table of common techniques and the full 14-tactic set.
--names input is technique / tactic names (or vendor labels), resolved
        by token match against the closed list.

--array (default for the *_techniques / *_tactics fields) emits an
        arraymap if-chain over a temp; otherwise a single arraycreate(if())
        wrap for one value.

Exit codes:
    0   snippet emitted
    1   argument error, or nothing resolved

Python 3.9+ stdlib only.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _xdm_schema import all_consts, load_xdm_consts  # noqa: E402
from xdm_const_mapper import best_match  # noqa: E402


_DEFAULT_FIELD = {
    "technique": "xdm.alert.mitre_techniques",
    "tactic": "xdm.alert.mitre_tactics",
}
_GROUP = {"technique": "MITRE_TECHNIQUE", "tactic": "MITRE_TACTIC"}

# The 14 ATT&CK tactics map 1:1 to the MITRE_TACTIC_* constants.
_TACTIC_IDS = {
    "TA0043": "MITRE_TACTIC_RECONNAISSANCE",
    "TA0042": "MITRE_TACTIC_RESOURCE_DEVELOPMENT",
    "TA0001": "MITRE_TACTIC_INITIAL_ACCESS",
    "TA0002": "MITRE_TACTIC_EXECUTION",
    "TA0003": "MITRE_TACTIC_PERSISTENCE",
    "TA0004": "MITRE_TACTIC_PRIVILEGE_ESCALATION",
    "TA0005": "MITRE_TACTIC_DEFENSE_EVASION",
    "TA0006": "MITRE_TACTIC_CREDENTIAL_ACCESS",
    "TA0007": "MITRE_TACTIC_DISCOVERY",
    "TA0008": "MITRE_TACTIC_LATERAL_MOVEMENT",
    "TA0009": "MITRE_TACTIC_COLLECTION",
    "TA0011": "MITRE_TACTIC_COMMAND_AND_CONTROL",
    "TA0010": "MITRE_TACTIC_EXFILTRATION",
    "TA0040": "MITRE_TACTIC_IMPACT",
}

# Curated common-technique ID -> constant-suffix table. Generous on
# purpose; every entry is validated against the documented list at
# runtime, so an entry that is not in references/xdm-const.md is dropped
# rather than emitted.
_TECHNIQUE_IDS = {
    "T1078": "MITRE_TECHNIQUE_VALID_ACCOUNTS",
    "T1059": "MITRE_TECHNIQUE_COMMAND_AND_SCRIPTING_INTERPRETER",
    "T1110": "MITRE_TECHNIQUE_BRUTE_FORCE",
    "T1566": "MITRE_TECHNIQUE_PHISHING",
    "T1133": "MITRE_TECHNIQUE_EXTERNAL_REMOTE_SERVICES",
    "T1021": "MITRE_TECHNIQUE_REMOTE_SERVICES",
    "T1496": "MITRE_TECHNIQUE_RESOURCE_HIJACKING",
    "T1087": "MITRE_TECHNIQUE_ACCOUNT_DISCOVERY",
    "T1098": "MITRE_TECHNIQUE_ACCOUNT_MANIPULATION",
    "T1136": "MITRE_TECHNIQUE_CREATE_ACCOUNT",
    "T1561": "MITRE_TECHNIQUE_DISK_WIPE",
}


def resolve_ids(kind: str, ids: List[str]) -> Tuple[List[Tuple[str, str]], List[str]]:
    """Return ([(id, full_const)], unmapped_ids). Drops any mapping whose
    constant is not in the documented list."""
    table = _TACTIC_IDS if kind == "tactic" else _TECHNIQUE_IDS
    known = all_consts()
    pairs: List[Tuple[str, str]] = []
    unmapped: List[str] = []
    seen: set = set()
    for raw in ids:
        i = raw.strip().upper()
        if not i or i in seen:
            continue
        seen.add(i)
        suffix = table.get(i)
        const = f"XDM_CONST.{suffix}" if suffix else None
        if const and const in known:
            pairs.append((raw.strip(), const))
        else:
            unmapped.append(raw.strip())
    return pairs, unmapped


def resolve_names(kind: str, names: List[str]) -> Tuple[List[Tuple[str, str]], List[str]]:
    group = _GROUP[kind]
    members = sorted(load_xdm_consts().get(group, set()))
    pairs: List[Tuple[str, str]] = []
    unmapped: List[str] = []
    seen: set = set()
    for raw in names:
        v = raw.strip()
        if not v or v in seen:
            continue
        seen.add(v)
        match = best_match(v, group, members)
        if match:
            pairs.append((v, match))
        else:
            unmapped.append(v)
    return pairs, unmapped


def render(
    field: str,
    pairs: List[Tuple[str, str]],
    temp: str,
    as_array: bool,
    unmapped: List[str],
) -> str:
    if not pairs:
        raise ValueError("no MITRE values resolved to a constant")

    if as_array:
        lines = [f"{field} = arraymap({temp}, if("]
        for key, const in pairs:
            lines.append(f'    "@element" = "{key}", {const},')
        lines.append("    null))")
    else:
        # Single value: wrap the if() in arraycreate so the array-typed
        # field still receives an array.
        lines = [f"{field} = arraycreate(if("]
        for key, const in pairs:
            lines.append(f'    {temp} = "{key}", {const},')
        lines.append("    null))")
    snippet = "\n".join(lines)
    if unmapped:
        snippet += "\n// unmapped (no MITRE constant; map by hand): " + ", ".join(unmapped)
    return snippet


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Map MITRE technique / tactic IDs or names to "
        "XDM_CONST.MITRE_* constants and emit the assignment."
    )
    ap.add_argument("--kind", choices=("technique", "tactic"), required=True)
    ap.add_argument("--ids", help="comma-separated ATT&CK IDs (T#### / TA####)")
    ap.add_argument("--names", help="comma-separated technique / tactic names")
    ap.add_argument("--field", default=None, help="override the target XDM field")
    ap.add_argument("--temp", default="_mitre_ids", help="source temp (default _mitre_ids)")
    ap.add_argument(
        "--array",
        dest="array",
        action="store_true",
        default=True,
        help="emit an arraymap chain over a temp (default)",
    )
    ap.add_argument(
        "--single",
        dest="array",
        action="store_false",
        help="emit a single arraycreate(if()) wrap instead of arraymap",
    )
    args = ap.parse_args(argv[1:])

    if not args.ids and not args.names:
        sys.stderr.write("error: provide --ids or --names\n")
        return 1

    field = args.field or _DEFAULT_FIELD[args.kind]
    if args.ids:
        items = [x for x in args.ids.split(",") if x.strip()]
        pairs, unmapped = resolve_ids(args.kind, items)
    else:
        items = [x for x in args.names.split(",") if x.strip()]
        pairs, unmapped = resolve_names(args.kind, items)

    try:
        snippet = render(field, pairs, args.temp, args.array, unmapped)
    except ValueError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1
    sys.stdout.write(snippet + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
