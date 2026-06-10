#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: GoCortexIO
"""scaffold_rule.py <worksheet.json>   (or: profile_log.py ... | scaffold_rule.py -)

Turn a profile_log.py worksheet into a complete starter MODEL rule. The
output is a deterministic, lint-clean `[MODEL: dataset=..._raw]` skeleton:
a MAPPED-header comment block, an extraction stage with one `_temp` per
mapped leaf, and an XDM drain stage wired from the worksheet's ranked
anchor candidates. Same worksheet in -> same rule out.

It is a starting point, not a finished rule. The drain stage covers the
high-confidence scalar mappings; fields that need an XDM_CONST if-chain,
banded scoring, or array-of-object projection are listed in the MAPPED
header's TODO / NOT MAPPED block for the author to complete.

The generated rule is run through the bundled linter before it is
printed; if any error-severity finding survives, the tool exits non-zero
and reports it, so a broken scaffold is never emitted silently.

Reads the worksheet from a path argument, or from stdin when the
argument is "-". Vendor / product / dataset default sensibly and can be
overridden with flags.

Exit codes:
    0   scaffold emitted and lints clean
    1   argument error, or the generated scaffold did not lint clean
    2   cannot read or parse the worksheet

Python 3.9+ stdlib only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _xdm_schema import load_xdm_paths  # noqa: E402
import lint_rule  # noqa: E402


# Formats whose fields arrive as parsed top-level columns (reference the
# column directly) versus formats carried in _raw_log as a JSON string
# (extract with json_extract_scalar).
_JSON_FORMATS = {"json", "jsonl"}
_COLUMN_FORMATS = {"kv", "csv", "tsv", "cef", "leef"}
_POSITIONAL_FORMATS = {"syslog-3164", "syslog-5424", "unknown"}

_DEFAULT_MIN_FREQUENCY = 3


def _sanitise_temp(leaf: str, used: set) -> str:
    """Build a unique ``_identifier`` from a leaf name."""
    base = re.sub(r"[^a-z0-9]+", "_", leaf.lower()).strip("_") or "field"
    name = "_" + base
    if name not in used:
        used.add(name)
        return name
    i = 2
    while f"{name}_{i}" in used:
        i += 1
    final = f"{name}_{i}"
    used.add(final)
    return final


def _extract_expr(fmt: str, path: str) -> Optional[str]:
    """Extraction RHS for a leaf, or None if it needs hand-authoring
    (array-of-object projection, positional parsing)."""
    if "[" in path:
        # Array element or header-pair path -- needs Pattern D' projection.
        return None
    if fmt in _JSON_FORMATS:
        return f'json_extract_scalar(_raw_log, "$.{path}")'
    if fmt in _COLUMN_FORMATS:
        # Parsed into a top-level column; reference it directly.
        return path.split(".")[-1]
    # Positional / unknown: emit a JSON stub but flag it in the header.
    return f'json_extract_scalar(_raw_log, "$.{path}")'


def _title(s: str) -> str:
    return " ".join(w.capitalize() for w in re.split(r"[^A-Za-z0-9]+", s) if w) or s


def scaffold(
    worksheet: dict,
    vendor: str,
    product: str,
    dataset: str,
    min_frequency: int = _DEFAULT_MIN_FREQUENCY,
) -> str:
    fmt = worksheet.get("detected_format", "unknown")
    fields = worksheet.get("fields") or []
    schema = load_xdm_paths()

    used_temps: set = set()
    # Targets the drain stage always emits itself; a candidate must not
    # produce a duplicate assignment to any of them.
    used_targets: set = {
        "xdm.observer.vendor",
        "xdm.observer.product",
        "xdm.event.type",
    }
    extractions: List[str] = []   # (temp, expr)
    drains: List[str] = []        # rendered "xdm.path = ..." lines
    mapping_rows: List[str] = []  # MAPPED-header "src -> dst" lines
    todo_rows: List[str] = []     # MAPPED-header TODO / NOT MAPPED lines

    for f in fields:
        path = f.get("path", "")
        leaf = f.get("leaf", path)
        cands = f.get("xdm_candidates") or []
        top = cands[0] if cands else None

        expr = _extract_expr(fmt, path)
        if expr is None:
            todo_rows.append(
                f"//   {path:<28} -- array / header-pair leaf; project per "
                "Pattern D' (see extraction-patterns.md)"
            )
            continue
        if not top or top.get("frequency", 0) < min_frequency:
            reason = (
                "no XDM anchor above the inclusion gate"
                if top
                else "no XDM anchor match"
            )
            todo_rows.append(f"//   {path:<28} -- {reason}")
            continue

        xdm_path = top["xdm_path"]
        meta = schema.get(xdm_path)
        if meta is None:
            todo_rows.append(
                f"//   {path:<28} -- candidate {xdm_path} not in schema; skip"
            )
            continue
        if xdm_path in used_targets:
            todo_rows.append(
                f"//   {path:<28} -- {xdm_path} already mapped; resolve the "
                "duplicate by hand"
            )
            continue

        temp = _sanitise_temp(leaf, used_temps)
        extractions.append(f"    {temp} = {expr}")

        if meta["const_group"]:
            # XDM_CONST-typed: a bare temp would lose the enum mapping.
            # Leave it for the author to complete with an if-chain.
            todo_rows.append(
                f"//   {path:<28} -> {xdm_path} (needs XDM_CONST."
                f"{meta['const_group']}_* if-chain)"
            )
            # Drain the temp into the description so it is not orphaned.
            drains.append(None)  # placeholder; replaced below
            extractions.pop()    # do not extract a temp we will not assign
            used_temps.discard(temp)
            continue

        used_targets.add(xdm_path)
        if meta["is_array"]:
            rhs = f"if({temp} != null, arraycreate({temp}), null)"
        elif meta["type"] == "Number":
            rhs = f"to_integer(to_number({temp}))"
        else:
            rhs = temp
        drains.append(f"    {xdm_path} = {rhs}")
        mapping_rows.append(f"//   {path:<28} -> {xdm_path}")

    drains = [d for d in drains if d is not None]

    # Assemble. Observer + event.type are always present.
    header = _build_header(vendor, product, dataset, fmt, mapping_rows, todo_rows)

    body: List[str] = [f"[MODEL: dataset={dataset}]", "filter", "    _raw_log != null"]
    if extractions:
        body.append("| alter")
        body.append(",\n".join(extractions))
    body.append("| alter")
    drain_lines = [
        f'    xdm.observer.vendor = "{vendor}"',
        f'    xdm.observer.product = "{product}"',
        '    xdm.event.type = "ALERT"',  # TODO: set the normalised category
    ]
    drain_lines.extend(drains)
    body.append(",\n".join(drain_lines))
    body.append(";")

    return header + "\n" + "\n".join(body) + "\n"


def _build_header(
    vendor: str,
    product: str,
    dataset: str,
    fmt: str,
    mapping_rows: List[str],
    todo_rows: List[str],
) -> str:
    lines = [
        "// SPDX-FileCopyrightText: GoCortexIO",
        "// SPDX-License-Identifier: AGPL-3.0-or-later",
        "//",
        f"// {vendor} {product} -- XDM Data Model Rule",
        f"// Dataset: {dataset}",
        f"// Vendor: {vendor} | Product: {product}",
        "//",
        f"// Starter rule scaffolded from a {fmt} sample. Review every",
        "// mapping, set xdm.event.type to the right normalised category,",
        "// and complete the TODO / NOT MAPPED entries below.",
        "//",
        "// ALERT / EVENT FIELD MAPPING",
        "// ---------------------------",
        "//   (hardcoded)                  -> xdm.observer.vendor",
        "//   (hardcoded)                  -> xdm.observer.product",
    ]
    lines.extend(mapping_rows)
    if fmt in _POSITIONAL_FORMATS:
        lines.append(
            "//"
        )
        lines.append(
            f"// NOTE: {fmt} is positional; the json_extract_scalar stubs "
            "below are placeholders -- switch to Pattern B (regextract + "
            "split + arrayindex)."
        )
    if todo_rows:
        lines.append("//")
        lines.append("// TODO / NOT MAPPED")
        lines.extend(todo_rows)
        lines.append("//   _time                        -- Cortex sets _time automatically")
    return "\n".join(lines)


def _load_worksheet(arg: str) -> dict:
    try:
        text = sys.stdin.read() if arg == "-" else Path(arg).read_text(encoding="utf-8")
    except OSError as exc:
        sys.stderr.write(f"error: cannot read worksheet {arg}: {exc}\n")
        sys.exit(2)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"error: worksheet is not valid JSON: {exc}\n")
        sys.exit(2)


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Scaffold a starter MODEL rule from a profile_log.py "
        "worksheet."
    )
    ap.add_argument("worksheet", help='worksheet JSON path, or "-" for stdin')
    ap.add_argument("--vendor", default="Vendor", help="vendor display name")
    ap.add_argument("--product", default="Product", help="product display name")
    ap.add_argument(
        "--dataset",
        default=None,
        help="dataset name (defaults to <vendor>_<product>_raw)",
    )
    ap.add_argument(
        "--min-frequency",
        type=int,
        default=_DEFAULT_MIN_FREQUENCY,
        help="anchor frequency inclusion gate (default 3)",
    )
    args = ap.parse_args(argv[1:])

    worksheet = _load_worksheet(args.worksheet)

    dataset = args.dataset
    if not dataset:
        v = re.sub(r"[^a-z0-9]+", "_", args.vendor.lower()).strip("_") or "vendor"
        p = re.sub(r"[^a-z0-9]+", "_", args.product.lower()).strip("_") or "product"
        dataset = f"{v}_{p}_raw"

    rule = scaffold(
        worksheet, args.vendor, args.product, dataset, args.min_frequency
    )

    # Self-gate: never emit a scaffold the linter would error on.
    findings = lint_rule.lint(rule)
    errors = [f for f in findings if f["severity"] == "error"]
    if errors:
        sys.stderr.write(
            "error: generated scaffold did not lint clean (this is a bug in "
            "scaffold_rule.py):\n"
        )
        for f in errors:
            sys.stderr.write(f"  line {f['line']} {f['rule_id']}: {f['message']}\n")
        return 1

    sys.stdout.write(rule)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
