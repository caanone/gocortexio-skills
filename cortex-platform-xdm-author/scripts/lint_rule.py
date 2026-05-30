#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: GoCortexIO
"""lint_rule.py <rule.xql>

Standalone syntactic linter for Cortex XSIAM XQL Data Model Rules.
Emits a JSON list of violations on stdout, ordered by source line.

Covers the parser-conformance rules whose detection is purely
syntactic (no XDM schema, no dataflow inference, no live tenant
state):

    ERR-012  Infix arithmetic in alter (use add / subtract / multiply / divide).
    ERR-013  Compound null guard inside if() predicate (X != null and/or Y != null).
    ERR-014  Bareword true / false equality on a string-typed column.
    ERR-015  to_number() result assigned to an integer-typed XDM field without to_integer().
    ERR-016  Invented xdm.event.start_time / end_time path.
    ERR-017  Bare arraymap(arr, "@element") passthrough on object arrays.
    ERR-018  Array function called on a known JSON-string column without the '-> []' cast.
    ERR-024  Sibling reference inside a single alter stage.
    ERR-027  MODEL reads a parser-stamped or undefined underscore field instead of deriving it from raw columns.
    INFO-012 Cascade root-cause hint when two parser-conformance violations land adjacent.

Out of scope (covered by the upstream IDE engine, which has the full
XDM schema, XDM_CONST closed-list, and dataflow inference):

    WARN-020 / WARN-030 / WARN-035  XDM array-vs-scalar type checks.
    ERR-025  Orphan temp hidden inside concat() / arraystring().
    INFO-006 fields - cleanup. Underscore temps are dropped by the dataset model
             layer at query time, so an explicit cleanup stage is not idiomatic.
             See references/extraction-patterns.md "A note on intermediate variables".

Python 3.9+ stdlib only.

Exit codes:
    0   no errors (warnings / info may still be present)
    1   one or more error-severity violations
    2   argument or I/O failure
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Iterable, List, Tuple


# --------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------


def _violation(
    rule_id: str,
    severity: str,
    line: int,
    message: str,
    recommendation: str = "",
) -> dict:
    out = {
        "rule_id": rule_id,
        "severity": severity,
        "line": line,
        "message": message,
    }
    if recommendation:
        out["recommendation"] = recommendation
    return out


# --------------------------------------------------------------------
# Source preparation
# --------------------------------------------------------------------


def _strip_line_comment(line: str) -> str:
    """Drop ``// ...`` line comments but preserve the original column
    layout for the surviving code prefix."""
    # Walk the line and cut at the first '//' that is outside a string.
    in_dq = False
    in_sq = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == '"' and not in_sq:
            in_dq = not in_dq
        elif ch == "'" and not in_dq:
            in_sq = not in_sq
        elif ch == "/" and i + 1 < len(line) and line[i + 1] == "/" \
                and not in_dq and not in_sq:
            return line[:i]
        i += 1
    return line


def _strip_strings(line: str) -> str:
    """Replace string-literal bodies with spaces (preserving length) so
    quoted operators / punctuation are invisible to regex scans but
    column positions still map back to ``line``."""

    def _blank(match: re.Match) -> str:
        body = match.group(0)
        return body[0] + " " * (len(body) - 2) + body[-1] if len(body) >= 2 else body

    line = re.sub(r'"(?:\\.|[^"\\])*"', _blank, line)
    line = re.sub(r"'(?:\\.|[^'\\])*'", _blank, line)
    return line


_STAGE_KEYWORDS = {
    "alter",
    "filter",
    "fields",
    "comp",
    "config",
    "target",
    "dedup",
    "sort",
    "limit",
    "join",
    "union",
    "bin",
}


def _classify_stages(code_lines: List[str]) -> Tuple[List[str], List[int]]:
    """Walk the source line by line, with paren-depth tracking, and
    label each line with its enclosing pipe stage and the index of the
    line that started that stage. A stage header at paren-depth > 0
    (inside a multi-line function call) does not switch stages."""
    stage_of: List[str] = []
    start_idx: List[int] = []
    cur_stage = ""
    cur_start = 0
    depth = 0
    header_re = re.compile(r"^\s*\|?\s*(\w+)\b")
    for i, raw in enumerate(code_lines):
        if depth == 0:
            m = header_re.match(raw)
            if m and m.group(1).lower() in _STAGE_KEYWORDS:
                cur_stage = m.group(1).lower()
                cur_start = i
        stage_of.append(cur_stage)
        start_idx.append(cur_start)
        for ch in _strip_strings(raw):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth = max(0, depth - 1)
    return stage_of, start_idx


# --------------------------------------------------------------------
# ERR-012  Infix arithmetic in alter
# --------------------------------------------------------------------


_INFIX_RE = re.compile(r"(?:[\w\)])\s*([\-+*/])\s*(?:[\w(])")


def _check_err012(code_lines: List[str], stage_of: List[str]) -> List[dict]:
    out: List[dict] = []
    seen: set = set()
    for i, raw in enumerate(code_lines):
        if stage_of[i] != "alter":
            continue
        cp = _strip_line_comment(raw)
        cleaned = _strip_strings(cp).replace("->", "@@")
        # Drop the LHS so '=' is not read as '+/-' neighbour glue.
        m = re.match(r"^\s*[\w\.]+\s*=", cleaned)
        rhs_start = m.end() if m else 0
        rhs = cleaned[rhs_start:]
        for hit in _INFIX_RE.finditer(rhs):
            key = (i, rhs_start + hit.start(1))
            if key in seen:
                continue
            seen.add(key)
            op = hit.group(1)
            out.append(
                _violation(
                    "ERR-012",
                    "error",
                    i + 1,
                    f"Infix arithmetic '{op}' in an alter assignment is "
                    "rejected by the Cortex parser. Use the function "
                    "form (add / subtract / multiply / divide).",
                    "Replace 'a - b' with 'subtract(a, b)', 'a + b' "
                    "with 'add(a, b)', etc. The parser produces a "
                    "cascade of unrelated-looking errors when infix "
                    "arithmetic is used inside alter.",
                )
            )
            break  # one ERR-012 per line is enough
    return out


# --------------------------------------------------------------------
# ERR-013  Compound null guard inside if() predicate
# --------------------------------------------------------------------


_ERR013_RE = re.compile(
    r"\bif\s*\(\s*[^,)]*?(?:!=|=)\s*null\s+(?:and|or)\s+[^,)]*?(?:!=|=)\s*null\s*,",
    re.IGNORECASE,
)


def _check_err013(joined_text: str, line_starts: List[int]) -> List[dict]:
    out: List[dict] = []
    for m in _ERR013_RE.finditer(joined_text):
        line_no = _line_at(line_starts, m.start()) + 1
        out.append(
            _violation(
                "ERR-013",
                "error",
                line_no,
                "Compound null guard ('X != null and/or Y != null') as "
                "the predicate of an if() is rejected by the Cortex "
                "parser.",
                "Drop the guard (null propagates through arithmetic "
                "and most functions), or split the check into nested "
                "if() / coalesce() calls.",
            )
        )
    return out


# --------------------------------------------------------------------
# ERR-014  Bareword true/false equality on string-typed column
# --------------------------------------------------------------------


_ERR014_FWD = re.compile(
    r"([A-Za-z_][\w\.]*\s*\([^()]*(?:\([^()]*\)[^()]*)*\)"
    r"(?:\s*->\s*\w+)?|[\w\.@\"\']+)\s*=\s*(true|false)\b"
)
_ERR014_REV_FWD = re.compile(r'\bto_boolean\s*\([^)]*\)\s*=\s*"(true|false)"')
_ERR014_REV_BWD = re.compile(r'"(true|false)"\s*=\s*to_boolean\s*\([^)]*\)')


def _lhs_is_string_typed(lhs: str) -> bool:
    if re.search(r"\bjson_extract_scalar\s*\(", lhs):
        return True
    if re.search(r"\bto_string\s*\(", lhs):
        return True
    if re.search(r"->\s*\w+\s*$", lhs):
        return True
    return False


def _check_err014(code_lines: List[str], stage_of: List[str]) -> List[dict]:
    out: List[dict] = []
    for i, raw in enumerate(code_lines):
        if stage_of[i] not in ("alter", "filter"):
            continue
        cp = _strip_line_comment(raw)
        for m in _ERR014_FWD.finditer(cp):
            lhs = m.group(1)
            literal = m.group(2)
            if re.search(r"to_boolean\s*\(", lhs, re.IGNORECASE):
                continue
            if lhs.startswith("xdm."):
                continue
            # Bare identifier 'name = true' usually an assignment.
            if re.fullmatch(r"[A-Za-z_]\w*", lhs.strip()):
                trim = cp.lstrip()
                if trim.startswith(lhs.strip()) or re.search(r",\s*$", cp[: m.start()]):
                    continue
            if not _lhs_is_string_typed(lhs):
                continue
            out.append(
                _violation(
                    "ERR-014",
                    "error",
                    i + 1,
                    f"'{lhs} = {literal}' compares against a bareword "
                    "boolean. The Cortex parser rejects this when the "
                    "column is string-typed.",
                    f"Quote the literal ('{lhs} = \"{literal}\"') if "
                    "the column is a string, or wrap the column: "
                    f"'to_boolean({lhs}) = {literal}'.",
                )
            )
        for m in _ERR014_REV_FWD.finditer(cp):
            out.append(
                _violation(
                    "ERR-014",
                    "error",
                    i + 1,
                    f'to_boolean(...) = "{m.group(1)}" compares a '
                    "Boolean expression against a quoted string. The "
                    "Cortex parser rejects this type mismatch.",
                    f"Drop the quotes and use the bareword: "
                    f"to_boolean(...) = {m.group(1)}.",
                )
            )
        for m in _ERR014_REV_BWD.finditer(cp):
            out.append(
                _violation(
                    "ERR-014",
                    "error",
                    i + 1,
                    f'"{m.group(1)}" = to_boolean(...) compares a '
                    "quoted string against a Boolean expression.",
                    f"Drop the quotes: {m.group(1)} = to_boolean(...).",
                )
            )
    return out


# --------------------------------------------------------------------
# ERR-015  to_number() into integer-typed XDM field
# --------------------------------------------------------------------


_INTEGER_XDM_TARGETS = {
    "xdm.event.duration",
    "xdm.source.port",
    "xdm.target.port",
    "xdm.intermediate.port",
    "xdm.network.bytes",
    "xdm.network.packets",
    "xdm.source.sent_bytes",
    "xdm.source.sent_packets",
    "xdm.target.sent_bytes",
    "xdm.target.sent_packets",
    "xdm.source.process.pid",
    "xdm.target.process.pid",
}


def _check_err015(code_lines: List[str]) -> List[dict]:
    out: List[dict] = []
    pat = re.compile(r"^\s*(xdm\.[\w.]+)\s*=\s*(.+)")
    for i, raw in enumerate(code_lines):
        cp = _strip_line_comment(raw)
        m = pat.match(cp)
        if not m:
            continue
        path = m.group(1)
        rhs = m.group(2)
        if path not in _INTEGER_XDM_TARGETS:
            continue
        if not re.search(r"\bto_number\s*\(", rhs):
            continue
        if re.search(r"\bto_integer\s*\(", rhs):
            continue
        out.append(
            _violation(
                "ERR-015",
                "error",
                i + 1,
                f"'{path}' is integer-typed but is assigned the result "
                "of to_number() (which returns float).",
                f"Wrap the to_number() call: {path} = "
                "to_integer(to_number(...)).",
            )
        )
    return out


# --------------------------------------------------------------------
# ERR-016  Invented xdm.event.start_time / end_time path
# --------------------------------------------------------------------


_ERR016_RE = re.compile(r"xdm\.event\.(start_time|end_time)\s*=")


def _check_err016(code_lines: List[str]) -> List[dict]:
    out: List[dict] = []
    for i, raw in enumerate(code_lines):
        cp = _strip_line_comment(raw)
        m = _ERR016_RE.search(cp)
        if m:
            out.append(
                _violation(
                    "ERR-016",
                    "error",
                    i + 1,
                    f"xdm.event.{m.group(1)} does not exist in the XDM "
                    "schema. Cortex rejects this with 'unknown field'.",
                    "Fold start/end millisecond pairs into "
                    "xdm.event.duration via subtract(). Cortex sets "
                    "_time automatically -- there is no separate XDM "
                    "start/end pair.",
                )
            )
    return out


# --------------------------------------------------------------------
# ERR-017  Bare arraymap(arr, "@element") passthrough
# --------------------------------------------------------------------


_BARE_ARRAYMAP_RE = re.compile(
    r'arraymap\s*\(\s*([^,]+?)\s*,\s*"@element"\s*\)(?!\s*->)'
)
_PRIM_CTOR_RE = re.compile(
    r"^(?:arraycreate|split|regextract|arrayrange|arrayconcat)\s*\("
)
_PRIM_VAR_RE = re.compile(
    r"(?:^|[,\s|])\s*(_?[A-Za-z_]\w*)\s*=\s*"
    r"(?:arraycreate|split|regextract|arrayrange|arrayconcat)\s*\("
)


def _check_err017(joined_text: str, code_lines: List[str], line_starts: List[int]) -> List[dict]:
    out: List[dict] = []
    primitive_vars: set = set()
    for m in _PRIM_VAR_RE.finditer(joined_text):
        primitive_vars.add(m.group(1))

    seen_lines: set = set()
    for i, raw in enumerate(code_lines):
        cp = _strip_line_comment(raw)
        for m in _BARE_ARRAYMAP_RE.finditer(cp):
            arg = m.group(1).strip()
            if _PRIM_CTOR_RE.match(arg):
                continue
            bare = re.fullmatch(r"[A-Za-z_]\w*", arg)
            if bare and bare.group(0) in primitive_vars:
                continue
            if i in seen_lines:
                continue
            seen_lines.add(i)
            out.append(
                _violation(
                    "ERR-017",
                    "error",
                    i + 1,
                    'arraymap(arr, "@element") returns the original '
                    "struct array. The Cortex parser rejects this "
                    "when the input is an array of objects.",
                    'Project ONE scalar at a time: arraymap(arr -> [], '
                    '"@element" -> field_name).',
                )
            )
    return out


# --------------------------------------------------------------------
# ERR-018  Missing '-> []' cast on JSON-string column
# --------------------------------------------------------------------


_JSON_STRING_COLS = {
    "tags",
    "filters",
    "detail",
    "labels",
    "annotations",
    "metadata",
    "raw_event",
}

_ARRAY_FN_CALL_RE = re.compile(
    r"\b(arraymap|arrayfilter|arraystring|arraydistinct|array_length)\s*\(\s*"
    r"([A-Za-z_][\w]*)\b"
)


def _check_err018(code_lines: List[str]) -> List[dict]:
    out: List[dict] = []
    seen: set = set()
    for i, raw in enumerate(code_lines):
        cp = _strip_line_comment(raw)
        for m in _ARRAY_FN_CALL_RE.finditer(cp):
            col = m.group(2)
            if col not in _JSON_STRING_COLS:
                continue
            # Skip if followed by '-> []' or '-> field'.
            tail = cp[m.end():]
            if re.match(r"\s*->\s*(\[\s*\]|\w+)", tail):
                continue
            key = (i, col)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                _violation(
                    "ERR-018",
                    "error",
                    i + 1,
                    f"JSON-string column '{col}' is passed to "
                    f"{m.group(1)}() without a '-> []' cast. The "
                    "Cortex parser rejects this with a type mismatch.",
                    f"Add the cast: {m.group(1)}({col} -> [], ...).",
                )
            )
    return out


# --------------------------------------------------------------------
# ERR-024  Sibling reference inside a single alter stage
# --------------------------------------------------------------------


_ASSIGN_RE = re.compile(r"^\s*(xdm\.[\w.]+|_[A-Za-z]\w*|[A-Za-z]\w*)\s*=")


def _check_err024(
    code_lines: List[str],
    stage_of: List[str],
    stage_start: List[int],
) -> List[dict]:
    out: List[dict] = []
    if not any(re.match(r"\s*\[MODEL:", ln) for ln in code_lines):
        return out

    # Collect assignment slots, paren-depth aware.
    depth = 0
    slots: List[dict] = []
    for i, raw in enumerate(code_lines):
        cp = _strip_line_comment(raw)
        start_depth = depth
        for ch in _strip_strings(cp):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth = max(0, depth - 1)
        if stage_of[i] != "alter" or start_depth > 0:
            continue
        m = _ASSIGN_RE.match(cp)
        if not m:
            continue
        name = m.group(1)
        if name in _STAGE_KEYWORDS or name in ("_time", "_raw_log"):
            continue
        kind = "xdm" if name.startswith("xdm.") else ("_temp" if name.startswith("_") else "bare")
        slots.append(
            {
                "name": name,
                "line": i + 1,
                "stage_start": stage_start[i],
                "kind": kind,
                "rhs_start": i,
                "rhs_end": i,
            }
        )

    slot_lines = {s["rhs_start"] for s in slots}
    for s in slots:
        end = len(code_lines) - 1
        for j in range(s["rhs_start"] + 1, len(code_lines)):
            if stage_start[j] != s["stage_start"]:
                end = j - 1
                break
            if j in slot_lines:
                end = j - 1
                break
        s["rhs_end"] = end

    temp_defs = [s for s in slots if s["kind"] == "_temp"]
    reported: set = set()
    for consumer in slots:
        siblings = [
            t
            for t in temp_defs
            if t["stage_start"] == consumer["stage_start"] and t["line"] != consumer["line"]
        ]
        if not siblings:
            continue
        rhs_text = "\n".join(
            _strip_line_comment(code_lines[k])
            for k in range(consumer["rhs_start"], consumer["rhs_end"] + 1)
        )
        # Drop the LHS prefix of the first line.
        rhs_body = re.sub(r"^\s*(?:xdm\.[\w.]+|_?[A-Za-z]\w*)\s*=", "", rhs_text)
        for sib in siblings:
            pat = re.compile(r"\b" + re.escape(sib["name"]) + r"\b")
            if not pat.search(rhs_body):
                continue
            key = (consumer["line"], sib["name"])
            if key in reported:
                continue
            reported.add(key)
            out.append(
                _violation(
                    "ERR-024",
                    "error",
                    consumer["line"],
                    f"'{consumer['name']}' references sibling temp "
                    f"'{sib['name']}' defined in the same alter "
                    "stage. Cortex evaluates all targets in one alter "
                    "in parallel and will reject this as 'unknown "
                    f"field {sib['name']}'.",
                    f"Split the alter stage: define '{sib['name']}' "
                    "in stage N, reference it in stage N+1.",
                )
            )
    return out


# --------------------------------------------------------------------
# ERR-027  MODEL reads an ingest-stamped or undefined underscore field
# --------------------------------------------------------------------


# Underscore fields that Cortex makes available to a MODEL rule without
# the rule assigning them. Everything else with a leading underscore is
# expected to be produced inside the rule (a modelled temp). A bare read
# of an underscore field that is NOT in this set and is never assigned a
# parser-independent value inside the rule is rejected statically as
# 'unknown field' -- the parser stamps it on a different (INGEST) rule,
# so it is absent from the dataset schema the MODEL validates against,
# and a coalesce(_anchor, fallback) wrapper does not help because the
# bare reference is rejected before the fallback can run.
_RESERVED_UNDERSCORE = {
    "_time",
    "_insert_time",
    "_raw_log",
    "_id",
    "_vendor",
    "_product",
    "_log_type",
    "_collector_name",
    "_collector_type",
    "_dataset",
    "_model",
    "_rule",
}

_USCORE_TOKEN = re.compile(r"(?<![A-Za-z0-9_])(_[A-Za-z]\w*)")
_USCORE_LHS = re.compile(r"^\s*(_[A-Za-z]\w*)\s*=(?!=)")
_ASSIGN_START = re.compile(r"^\s*[\w.]+\s*=(?!=)")


def _check_err027(
    code_lines: List[str],
    stage_of: List[str],
    stage_start: List[int],
) -> List[dict]:
    if not any(re.match(r"\s*\[MODEL:", ln) for ln in code_lines):
        return []

    cleaned = [_strip_strings(_strip_line_comment(ln)) for ln in code_lines]

    # 1. Collect underscore-LHS assignment slots inside alter stages, at
    #    paren-depth 0, with their RHS line span (mirrors ERR-024).
    depth = 0
    slots: List[dict] = []
    for i, cp in enumerate(cleaned):
        start_depth = depth
        for ch in cp:
            if ch in "([":
                depth += 1
            elif ch in ")]":
                depth = max(0, depth - 1)
        if stage_of[i] != "alter" or start_depth > 0:
            continue
        m = _USCORE_LHS.match(cp)
        if not m:
            continue
        slots.append({"name": m.group(1), "line": i, "stage_start": stage_start[i]})

    # An assignment's RHS runs until the next comma-separated alter term
    # (any LHS: underscore temp, tmp_*, or xdm.* path) or the end of the
    # stage. Stopping only at the next underscore slot would over-extend a
    # single-line assignment across later siblings and misread a self-ref.
    for s in slots:
        end = len(cleaned) - 1
        for j in range(s["line"] + 1, len(cleaned)):
            if stage_start[j] != s["stage_start"] or _ASSIGN_START.match(cleaned[j]):
                end = j - 1
                break
        s["rhs_end"] = end

    # 2. produced_clean: a field with at least one assignment whose RHS
    #    does not read the field itself (i.e. it is derived from raw
    #    columns, not lifted from its own parser-stamped value).
    assigned: set = set()
    produced_clean: set = set()
    for s in slots:
        assigned.add(s["name"])
        rhs = "\n".join(cleaned[s["line"]: s["rhs_end"] + 1])
        rhs = re.sub(r"^\s*_[A-Za-z]\w*\s*=", "", rhs, count=1)
        self_ref = re.search(
            r"(?<![A-Za-z0-9_])" + re.escape(s["name"]) + r"(?![A-Za-z0-9_])",
            rhs,
        )
        if not self_ref:
            produced_clean.add(s["name"])

    # 3. Reads: every underscore token that is not the single LHS token
    #    of its own line, recorded at first occurrence.
    first_read_line: dict = {}
    for i, cp in enumerate(cleaned):
        lhs = _USCORE_LHS.match(cp)
        lhs_name = lhs.group(1) if lhs else None
        lhs_skipped = False
        for m in _USCORE_TOKEN.finditer(cp):
            name = m.group(1)
            if name == lhs_name and not lhs_skipped:
                lhs_skipped = True
                continue
            first_read_line.setdefault(name, i)

    out: List[dict] = []
    for name, line_idx in sorted(first_read_line.items(), key=lambda kv: kv[1]):
        if name in _RESERVED_UNDERSCORE or name in produced_clean:
            continue
        if name in assigned:
            detail = (
                f"'{name}' is only ever assigned from its own value "
                f"(e.g. coalesce({name}, ...)), so it still reads the "
                "parser-stamped column."
            )
        else:
            detail = f"'{name}' is read but never assigned in this rule."
        out.append(
            _violation(
                "ERR-027",
                "error",
                line_idx + 1,
                f"MODEL rule reads underscore field '{name}' that is not "
                "produced from raw columns within the rule. "
                + detail
                + " Cortex validates MODEL rules statically against the "
                "dataset schema and rejects a parser-only field as "
                f"'unknown field {name}' before any coalesce() fallback "
                "runs.",
                "Make the MODEL self-sufficient: derive the value from "
                "raw dataset columns inside this rule. Drop the bare "
                f"'{name}' from a coalesce({name}, fallback) so only the "
                "modelled fallback remains, or remove the reference if no "
                "raw source exists.",
            )
        )
    return out


# --------------------------------------------------------------------
# INFO-012  Cascade root-cause hint
# --------------------------------------------------------------------


_CASCADE_RULES = {"ERR-012", "ERR-013", "ERR-014", "ERR-015", "ERR-017", "ERR-018"}


def _cascade_hint(violations: List[dict]) -> List[dict]:
    rel = sorted(
        [v for v in violations if v["rule_id"] in _CASCADE_RULES],
        key=lambda v: v["line"],
    )
    if len(rel) < 2:
        return []
    # Group entries where each consecutive pair sits within 1 line.
    first = rel[0]
    out: List[dict] = []
    cluster_size = 1
    for prev, cur in zip(rel, rel[1:]):
        if cur["line"] - prev["line"] <= 1:
            cluster_size += 1
        else:
            cluster_size = 1
        if cluster_size == 2:
            out.append(
                _violation(
                    "INFO-012",
                    "info",
                    first["line"],
                    "Multiple parser-conformance violations land on "
                    "adjacent lines. The earliest is almost always "
                    "the root cause; the rest are cascade noise.",
                    f"Fix the violation on line {first['line']} "
                    "first, then re-lint. Subsequent cascade errors "
                    "typically clear by themselves.",
                )
            )
            break
    return out


# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------


def _line_at(line_starts: List[int], offset: int) -> int:
    """Binary-ish search: return the 0-indexed line that contains
    ``offset`` in the joined-text representation."""
    lo, hi = 0, len(line_starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if line_starts[mid] <= offset:
            lo = mid
        else:
            hi = mid - 1
    return lo


def _join_with_offsets(lines: List[str]) -> Tuple[str, List[int]]:
    out_parts: List[str] = []
    offsets: List[int] = []
    pos = 0
    for ln in lines:
        offsets.append(pos)
        out_parts.append(ln)
        pos += len(ln) + 1
    return "\n".join(out_parts), offsets


# --------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------


def lint(source: str) -> List[dict]:
    """Return the ordered list of violations for ``source``."""
    code_lines = source.splitlines()
    stage_of, stage_start = _classify_stages(code_lines)
    joined, line_starts = _join_with_offsets(
        [_strip_line_comment(ln) for ln in code_lines]
    )

    findings: List[dict] = []
    findings += _check_err012(code_lines, stage_of)
    findings += _check_err013(joined, line_starts)
    findings += _check_err014(code_lines, stage_of)
    findings += _check_err015(code_lines)
    findings += _check_err016(code_lines)
    findings += _check_err017(joined, code_lines, line_starts)
    findings += _check_err018(code_lines)
    findings += _check_err024(code_lines, stage_of, stage_start)
    findings += _check_err027(code_lines, stage_of, stage_start)

    findings.sort(key=lambda v: (v["line"], v["rule_id"]))
    findings += _cascade_hint(findings)
    findings.sort(key=lambda v: (v["line"], v["rule_id"]))
    return findings


def _format_text(violations: Iterable[dict]) -> str:
    parts = []
    for v in violations:
        parts.append(
            f"[{v['severity'].upper():>7}] line {v['line']:>4} "
            f"{v['rule_id']}: {v['message']}"
        )
        rec = v.get("recommendation")
        if rec:
            parts.append(f"           -> {rec}")
    return "\n".join(parts)


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Standalone syntactic linter for Cortex XSIAM XQL "
        "Data Model Rules. JSON on stdout."
    )
    ap.add_argument("rule_file", help="path to a single .xql file")
    ap.add_argument(
        "--format",
        choices=("json", "text"),
        default="json",
        help="output format (default: json)",
    )
    args = ap.parse_args(argv[1:])

    path = Path(args.rule_file)
    if not path.is_file():
        sys.stderr.write(f"error: {path} not found or not a file\n")
        return 2
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as exc:
        sys.stderr.write(f"error: cannot read {path}: {exc}\n")
        return 2

    findings = lint(source)

    if args.format == "json":
        sys.stdout.write(json.dumps(findings, indent=2) + "\n")
    else:
        if findings:
            sys.stdout.write(_format_text(findings) + "\n")
        else:
            sys.stdout.write("no violations\n")

    if any(v["severity"] == "error" for v in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
