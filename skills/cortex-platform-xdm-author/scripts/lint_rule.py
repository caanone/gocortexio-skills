#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: GoCortexIO
"""lint_rule.py <rule.xql>

Standalone linter for Cortex XSIAM XQL Data Model Rules. Emits a JSON
list of violations on stdout, ordered by source line. Reads the XDM
schema and XDM_CONST closed lists from the bundle's own references
(via _xdm_schema), and runs a dataflow pass over the rule, so it
performs the schema and dataflow checks offline with no external state.

Structural and parser-conformance checks:

    ERR-009  Missing terminal semicolon.
    ERR-010  Trailing comma before the terminal semicolon.
    ERR-011  Self-referencing xdm.* field (reads itself on its own RHS).
    ERR-012  Infix arithmetic in alter (use add / subtract / multiply / divide).
    ERR-013  Compound null guard inside if() predicate (X != null and/or Y != null).
    ERR-014  Bareword true / false equality on a string-typed column.
    ERR-015  to_number() result assigned to an integer-typed XDM field without to_integer().
    ERR-016  Invented xdm.event.start_time / end_time path.
    ERR-017  Bare arraymap(arr, "@element") passthrough on object arrays.
    ERR-018  Array function called on a known JSON-string column without the '-> []' cast.
    ERR-024  Sibling reference inside a single alter stage.
    ERR-027  MODEL reads a parser-stamped or undefined underscore field instead of deriving it from raw columns.
    WARN-015 Quoted dataset name in the MODEL header.
    WARN-017 Leading pipe on the first stage after the MODEL header.
    WARN-018 _time assigned in a MODEL rule.
    INFO-012 Cascade root-cause hint when two parser-conformance violations land adjacent.

Schema-aware checks (XDM schema + XDM_CONST loaded from references):

    ERR-020  Invented xdm.* assignment target (not a real leaf field).
    WARN-014 Quoted XDM_CONST value (dropped as a string literal).
    WARN-035 Array-typed XDM field assigned a scalar value.
    WARN-037 Log-level word (warning / error / notice / debug) echoed into
             xdm.alert.severity instead of a proper band.

Dataflow checks (reach + array-typing over the rule's temps):

    ERR-019  Underscore temp never reaches an xdm.* assignment (_gc_raw).
    ERR-025  Temp whose only consumer is inside a concat() / arraystring() body (_gc_raw).

ERR-019 and ERR-025 are a hard block only on _gc_raw datasets; on plain
_raw datasets Cortex tolerates the same shapes, so the linter scopes
them to _gc_raw.

INFO-006 (fields - cleanup) is deliberately NOT emitted: underscore
temps are dropped by the dataset model layer at query time, so an
explicit cleanup stage is not idiomatic in a MODEL rule. See
references/extraction-patterns.md "A note on intermediate variables".

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

# Sibling shared loader. The bundle ships scripts/ as a flat directory; this
# insert lets lint_rule.py import _xdm_schema whether run as a script or
# imported by the test suite via importlib.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _xdm_schema import (  # noqa: E402
    load_xdm_paths,
    xdm_path_exists,
    xdm_path_is_array,
)


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
# Dataflow analyser
#
# Port of the engine's analyseDataflow: collects every `name =` def
# inside alter stages (paren-depth 0), computes each def's multi-line
# RHS window, then derives two sets:
#   reachable   -- defs that flow into an xdm.* assignment, directly or
#                  transitively through other reachable defs' RHS.
#   array_typed -- defs whose RHS produces an array, propagated through
#                  bare-reference chains.
# ERR-019 (unused temp) and the array-vs-scalar warnings consume these.
# --------------------------------------------------------------------


_ARRAY_PRODUCING_FNS = {
    "arraycreate", "arrayconcat", "arraydistinct", "arraymap",
    "arrayfilter", "arraymerge", "arraypop", "arrayrange",
    "arrayresize", "split", "regextract", "json_extract_array",
    "json_extract_scalar_array", "values",
    "object_keys", "object_values",
}
_ARRAY_FN_RE = re.compile(r"\b(" + "|".join(sorted(_ARRAY_PRODUCING_FNS)) + r")\s*\(")
# Arrow array access. Matches both the JSON-string cast ``col -> []`` and an
# array-typed sub-field access ``col -> field[]`` / ``col -> a.b[]``; both
# yield an array. (The engine only matched ``-> []``; recognising the named
# form too removes a false-positive WARN-035 on rules that read a native
# array sub-field via the arrow operator.)
_ARRAY_SUFFIX_RE = re.compile(r"->\s*[\w.]*\[\s*\]")
_XDM_ASSIGN_RE = re.compile(r"xdm\.[\w.]+\s*=")
_DF_STAGE_RE = re.compile(r"^\s*\|\s*(\w+)\b")
_DF_DEF_RE = re.compile(r"^\s*([a-zA-Z_]\w*)\s*=")
_DF_RESERVED = {"_time", "_raw_log"}
_DF_STAGE_WORDS = {"alter", "filter", "comp", "config", "target"}


def _split_top_level_args(s: str) -> List[str]:
    """Split a function-arg list at top-level commas (paren and string aware)."""
    out: List[str] = []
    depth = 0
    start = 0
    in_str = None
    for i, ch in enumerate(s):
        if in_str:
            if ch == in_str and s[i - 1] != "\\":
                in_str = None
            continue
        if ch in ('"', "'"):
            in_str = ch
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(s[start:i])
            start = i + 1
    out.append(s[start:])
    return [a.strip() for a in out if a.strip()]


def _rhs_is_array_typed(rhs: str, known_array_vars: set) -> bool:
    """Decide whether an RHS expression produces an array. ``known_array_vars``
    feeds in already-classified array temps so chains propagate."""
    t = re.sub(r"[,;]\s*$", "", rhs.strip())
    if not t:
        return False
    if _ARRAY_SUFFIX_RE.search(t):
        return True
    fn_match = re.match(r"^([a-zA-Z_]\w*)\s*\(", t)
    if fn_match:
        # Verify the matching close paren is at the end of the expression.
        depth = 0
        close_idx = -1
        in_str = None
        for i in range(len(fn_match.group(0)) - 1, len(t)):
            ch = t[i]
            if in_str:
                if ch == in_str and t[i - 1] != "\\":
                    in_str = None
                continue
            if ch in ('"', "'"):
                in_str = ch
                continue
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    close_idx = i
                    break
        fn_name = fn_match.group(1).lower()
        wraps_whole = close_idx == len(t) - 1
        if wraps_whole:
            if fn_name in _ARRAY_PRODUCING_FNS:
                return True
            if fn_name in ("if", "coalesce"):
                inner = t[len(fn_match.group(0)):close_idx]
                args = _split_top_level_args(inner)
                # if(cond, then, ..., else): value positions are everything
                # after the first arg. coalesce: every arg is a value.
                value_args = args[1:] if fn_name == "if" else args
                for a in value_args:
                    cleaned = a.strip()
                    if cleaned in ("null", ""):
                        continue
                    if _rhs_is_array_typed(cleaned, known_array_vars):
                        return True
                return False
            # Other scalar-returning calls (arraystring, arrayindex,
            # array_length, to_string, concat, ...) are not array-typed.
            return False
    bare = re.match(r"^([a-zA-Z_]\w*)\s*$", t)
    if bare and bare.group(1) in known_array_vars:
        return True
    if _ARRAY_FN_RE.search(t):
        return True
    return False


def _analyse_dataflow(code_lines: List[str]) -> dict:
    """Return ``{"defs": [...], "reachable": set, "array_typed": set}``.

    ``defs`` is a list of ``{name, line (1-indexed), is_underscore,
    rhs_text}``. Mirrors the engine's analyseDataflow exactly so the
    bundle linter's verdicts match the full engine offline.
    """
    all_parts: List[str] = []
    for raw in code_lines:
        if raw.lstrip().startswith("//"):
            all_parts.append("")
        else:
            all_parts.append(raw.split("//", 1)[0])

    # Stage tracking -- only collect defs inside alter stages.
    cur_stage = ""
    stage_of: List[str] = []
    for cp in all_parts:
        sm = _DF_STAGE_RE.match(cp)
        if sm:
            cur_stage = sm.group(1).lower()
        stage_of.append(cur_stage)

    # Paren-aware def detection at depth 0.
    defs: List[dict] = []
    paren_depth = 0
    for i, cp in enumerate(all_parts):
        stage = stage_of[i]
        start_depth = paren_depth
        stripped = re.sub(r'"[^"]*"', '""', cp)
        stripped = re.sub(r"'[^']*'", "''", stripped)
        for ch in stripped:
            if ch == "(":
                paren_depth += 1
            elif ch == ")":
                paren_depth = max(0, paren_depth - 1)
        if stage and stage != "alter":
            continue
        if start_depth > 0:
            continue
        m = _DF_DEF_RE.match(cp)
        if not m:
            continue
        name = m.group(1)
        if name in _DF_RESERVED or name in _DF_STAGE_WORDS:
            continue
        defs.append(
            {"name": name, "line": i + 1, "is_underscore": name.startswith("_"), "rhs_text": ""}
        )

    real_def_lines = {d["line"] - 1 for d in defs}

    def _is_stage_start(cp: str) -> bool:
        return bool(re.match(r"^\s*\|\s*\w+", cp))

    def _rhs_end(start: int) -> int:
        end = len(all_parts) - 1
        for j in range(start + 1, len(all_parts)):
            cp = all_parts[j]
            if _is_stage_start(cp) or j in real_def_lines or _XDM_ASSIGN_RE.search(cp):
                return j - 1
        return end

    for d in defs:
        start = d["line"] - 1
        d["rhs_text"] = "\n".join(all_parts[start: _rhs_end(start) + 1])

    # Locate the xdm.* assignment block (first xdm.* assignment to EOF).
    first_xdm_idx = -1
    for i, cp in enumerate(all_parts):
        if _XDM_ASSIGN_RE.search(cp):
            first_xdm_idx = i
            break

    reachable: set = set()
    if first_xdm_idx >= 0:
        # Seed: a def is reachable if its name appears in the xdm.* block
        # OUTSIDE its own def window (a self-reference must not count).
        for d in defs:
            if d["name"] in reachable:
                continue
            skip_idx: set = set()
            for dd in defs:
                if dd["name"] != d["name"]:
                    continue
                start = dd["line"] - 1
                for k in range(start, _rhs_end(start) + 1):
                    skip_idx.add(k)
            blob = [
                "" if k in skip_idx else all_parts[k]
                for k in range(first_xdm_idx, len(all_parts))
            ]
            if re.search(r"\b" + re.escape(d["name"]) + r"\b", "\n".join(blob)):
                reachable.add(d["name"])
        # Transitive expansion through reachable defs' RHS.
        changed = True
        while changed:
            changed = False
            for reach_name in list(reachable):
                for cand in defs:
                    if cand["name"] in reachable or cand["name"] == reach_name:
                        continue
                    for d in defs:
                        if d["name"] != reach_name:
                            continue
                        if re.search(r"\b" + re.escape(cand["name"]) + r"\b", d["rhs_text"]):
                            reachable.add(cand["name"])
                            changed = True

    # Array-typed BFS.
    array_typed: set = set()
    changed = True
    while changed:
        changed = False
        for d in defs:
            if d["name"] in array_typed:
                continue
            rhs = d["rhs_text"]
            eq = rhs.find("=")
            if eq >= 0:
                rhs = rhs[eq + 1:]
            if _rhs_is_array_typed(rhs, array_typed):
                array_typed.add(d["name"])
                changed = True

    return {"defs": defs, "reachable": reachable, "array_typed": array_typed}


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
# Schema-aware + dataflow rules
# --------------------------------------------------------------------


def _is_model(code_lines: List[str]) -> bool:
    return any(re.match(r"\s*\[MODEL:", ln) for ln in code_lines)


_GC_RAW_HEADER_RE = re.compile(r'\s*\[MODEL:\s*dataset\s*=\s*"?(\w+)')


def _is_gc_raw(code_lines: List[str]) -> bool:
    """True when the MODEL header targets a ``_gc_raw`` dataset. The unused-
    field rejections (ERR-019, ERR-025) are a hard block only on GoCortex
    ``_gc_raw`` datasets; plain ``_raw`` datasets tolerate the same shapes,
    so these checks are scoped to ``_gc_raw`` to match Cortex."""
    for ln in code_lines:
        m = _GC_RAW_HEADER_RE.match(ln)
        if m:
            return m.group(1).endswith("_gc_raw")
    return False


# ----- ERR-019  unused underscore temp (never reaches an xdm.* assignment)


def _check_err019(code_lines: List[str], df: dict) -> List[dict]:
    if not _is_model(code_lines) or not _is_gc_raw(code_lines):
        return []
    out: List[dict] = []
    seen: set = set()
    for d in df["defs"]:
        if not d["is_underscore"] or d["name"] in seen:
            continue
        seen.add(d["name"])
        if d["name"] in df["reachable"]:
            continue
        out.append(
            _violation(
                "ERR-019",
                "error",
                d["line"],
                f"Underscore variable '{d['name']}' is defined but never "
                "reaches any xdm.* assignment, even through other "
                "_-prefixed intermediaries. Cortex rejects this on "
                "_gc_raw datasets as 'unused field'.",
                f"Map the tail of the chain from '{d['name']}' to an xdm.* "
                "field, or remove the dead intermediary chain.",
            )
        )
    return out


# ----- ERR-025  orphan temp whose only consumer is inside concat/arraystring


_HIDING_FNS = ("concat", "arraystring")


def _inside_hiding_fn(full_text: str, abs_start: int) -> bool:
    """Walk back from a reference to find its enclosing call; True if that
    call (or an outer call) is concat() / arraystring()."""
    before = full_text[:abs_start]
    depth = 0
    k = len(before) - 1
    while k >= 0:
        ch = before[k]
        if ch == ")":
            depth += 1
        elif ch == "(":
            if depth == 0:
                head = before[:k]
                fm = re.search(r"([A-Za-z_]\w*)\s*$", head)
                if not fm:
                    return False
                if fm.group(1).lower() in _HIDING_FNS:
                    return True
                return _inside_hiding_fn(full_text, k)
            depth -= 1
        k -= 1
    return False


def _check_err025(code_lines: List[str]) -> List[dict]:
    if not _is_model(code_lines) or not _is_gc_raw(code_lines):
        return []
    cl: List[str] = []
    for raw in code_lines:
        cl.append("" if raw.lstrip().startswith("//") else raw.split("//", 1)[0])
    defs: List[dict] = []
    pd = 0
    for i, cp in enumerate(cl):
        start_depth = pd
        st = re.sub(r'"[^"]*"', '""', cp)
        st = re.sub(r"'[^']*'", "''", st)
        for ch in st:
            if ch == "(":
                pd += 1
            elif ch == ")":
                pd = max(0, pd - 1)
        if start_depth > 0:
            continue
        m = re.match(r"^\s*(_[A-Za-z]\w*)\s*=", cp)
        if not m or m.group(1) in ("_time", "_raw_log"):
            continue
        defs.append({"name": m.group(1), "line": i + 1})
    if not defs:
        return []
    full = "\n".join(cl)
    offs: List[int] = []
    off = 0
    for ln in cl:
        offs.append(off)
        off += len(ln) + 1
    out: List[dict] = []
    for d in defs:
        rx = re.compile(r"\b" + re.escape(d["name"]) + r"\b")
        refs: List[int] = []
        for m in rx.finditer(full):
            li = 0
            for idx, o in enumerate(offs):
                if o <= m.start():
                    li = idx
                else:
                    break
            if li + 1 == d["line"]:
                continue
            refs.append(m.start())
        if not refs:
            continue
        if all(_inside_hiding_fn(full, r) for r in refs):
            out.append(
                _violation(
                    "ERR-025",
                    "error",
                    d["line"],
                    f"'{d['name']}' is only referenced inside concat() / "
                    "arraystring() bodies. Cortex's unused-field tracer does "
                    "not follow into these function bodies and reports it as "
                    "'unused field' on _gc_raw datasets.",
                    f"Inline the derivation of '{d['name']}' directly into "
                    "the concat() / arraystring() call, or drain it through a "
                    "bareword identity assignment to an xdm.* field before the "
                    "consumer.",
                )
            )
    return out


# ----- ERR-020  invented xdm.* assignment target (not a real leaf field)


def _edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if not la:
        return lb
    if not lb:
        return la
    prev = list(range(lb + 1))
    for i in range(la):
        cur = [i + 1] + [0] * lb
        for j in range(lb):
            cost = 0 if a[i] == b[j] else 1
            cur[j + 1] = min(cur[j] + 1, prev[j + 1] + 1, prev[j] + cost)
        prev = cur
    return prev[lb]


def _check_err020(code_lines: List[str]) -> List[dict]:
    if not _is_model(code_lines):
        return []
    known = list(load_xdm_paths().keys())
    out: List[dict] = []
    seen: set = set()
    lhs_re = re.compile(r"^\s*(xdm\.[\w.]+)\s*=(?!=)")
    for i, raw in enumerate(code_lines):
        if raw.lstrip().startswith("//"):
            continue
        m = lhs_re.match(raw.split("//", 1)[0])
        if not m:
            continue
        path = m.group(1)
        if path in seen:
            continue
        seen.add(path)
        if xdm_path_exists(path):
            continue
        scored = sorted(known, key=lambda p: _edit_distance(path, p))[:3]
        hint = f" Closest matches: {', '.join(scored)}." if scored else ""
        out.append(
            _violation(
                "ERR-020",
                "error",
                i + 1,
                f"'{path}' is not a known XDM field. Cortex rejects "
                f"assignments to invented paths.{hint}",
                "Use a real XDM field from references/xdm-schema.md, or pick "
                "the closest semantic match above.",
            )
        )
    return out


# ----- WARN-014  quoted XDM_CONST value


_QUOTED_CONST_RE = re.compile(r'"(XDM_CONST\.[A-Z][A-Z0-9_]*)"')


def _check_warn014(code_lines: List[str]) -> List[dict]:
    out: List[dict] = []
    for i, raw in enumerate(code_lines):
        if raw.lstrip().startswith("//"):
            continue
        for m in _QUOTED_CONST_RE.finditer(raw.split("//", 1)[0]):
            out.append(
                _violation(
                    "WARN-014",
                    "warning",
                    i + 1,
                    f"XDM_CONST value {m.group(1)} is quoted. Cortex treats a "
                    "quoted constant as a string literal and drops the "
                    "mapping.",
                    f"Remove the quotes: {m.group(1)}.",
                )
            )
    return out


# ----- WARN-015  quoted dataset name in the MODEL header


_MODEL_QUOTED_DS = re.compile(r'\[MODEL:\s*dataset\s*=\s*"')


def _check_warn015(code_lines: List[str]) -> List[dict]:
    out: List[dict] = []
    for i, raw in enumerate(code_lines):
        if _MODEL_QUOTED_DS.search(raw):
            out.append(
                _violation(
                    "WARN-015",
                    "warning",
                    i + 1,
                    "Dataset name is quoted in the MODEL header. MODEL "
                    "declarations use an unquoted dataset name.",
                    'Write dataset=name_raw, not dataset="name_raw".',
                )
            )
    return out


# ----- WARN-017  leading pipe on the first stage after the MODEL header


def _check_warn017(code_lines: List[str]) -> List[dict]:
    out: List[dict] = []
    seen_model = False
    for i, raw in enumerate(code_lines):
        if re.match(r"\s*\[MODEL:", raw):
            seen_model = True
            continue
        if not seen_model:
            continue
        if not raw.strip() or raw.lstrip().startswith("//"):
            continue
        if raw.lstrip().startswith("|"):
            out.append(
                _violation(
                    "WARN-017",
                    "warning",
                    i + 1,
                    "The first stage after the MODEL header has a leading "
                    "pipe. Write 'alter' or 'filter' directly.",
                    "Remove the leading '|' on the first stage.",
                )
            )
        break
    return out


# ----- WARN-018  _time assigned in a MODEL rule


_TIME_ASSIGN_RE = re.compile(r"^\s*_time\s*=(?!=)")


def _check_warn018(code_lines: List[str]) -> List[dict]:
    if not _is_model(code_lines):
        return []
    out: List[dict] = []
    for i, raw in enumerate(code_lines):
        if raw.lstrip().startswith("//"):
            continue
        if _TIME_ASSIGN_RE.match(raw.split("//", 1)[0]):
            out.append(
                _violation(
                    "WARN-018",
                    "warning",
                    i + 1,
                    "_time is assigned in a MODEL rule. Cortex sets the event "
                    "timestamp during INGEST; MODEL rules must not assign "
                    "_time.",
                    "Remove the _time assignment.",
                )
            )
    return out


# ----- ERR-009 / ERR-010  terminal semicolon + no trailing comma


def _check_err009_010(code_lines: List[str]) -> List[dict]:
    last_idx = -1
    parts: List[str] = []
    for i, raw in enumerate(code_lines):
        cp = _strip_line_comment(raw)
        parts.append(cp)
        if cp.strip():
            last_idx = i
    if last_idx < 0:
        return []
    tail = "\n".join(parts).rstrip()
    if not tail.endswith(";"):
        return [
            _violation(
                "ERR-009",
                "error",
                last_idx + 1,
                "Rule does not end with a terminal semicolon. The Cortex IDE "
                "rejects a rule with no ';' at the end.",
                "End the rule with ';'.",
            )
        ]
    pre = tail[:-1].rstrip()
    if pre.endswith(","):
        return [
            _violation(
                "ERR-010",
                "error",
                last_idx + 1,
                "Trailing comma before the terminal semicolon. The last field "
                "assignment must not have a trailing comma.",
                "Remove the comma before ';'.",
            )
        ]
    return []


# ----- ERR-011  self-referencing xdm field


def _check_err011(code_lines: List[str]) -> List[dict]:
    out: List[dict] = []
    pat = re.compile(r"^\s*(xdm\.[\w.]+)\s*=(?!=)(.*)$")
    for i, raw in enumerate(code_lines):
        if raw.lstrip().startswith("//"):
            continue
        m = pat.match(_strip_line_comment(raw))
        if not m:
            continue
        lhs, rhs = m.group(1), m.group(2)
        if re.search(r"(?<![\w.])" + re.escape(lhs) + r"(?![\w])", rhs):
            out.append(
                _violation(
                    "ERR-011",
                    "error",
                    i + 1,
                    f"{lhs} references itself on the right-hand side of its "
                    "own assignment. Cortex rejects self-referencing XDM "
                    "fields.",
                    f"Assign {lhs} from a temp or raw column, not from "
                    f"coalesce({lhs}, ...) or any expression that reads "
                    f"{lhs}.",
                )
            )
    return out


# ----- WARN-035  array-typed XDM field assigned a scalar value


_WARN035_ASSIGN_RE = re.compile(r"^(xdm\.[\w.]+)\s*=\s*(.+?)\s*$")


def _check_warn035(code_lines: List[str], df: dict) -> List[dict]:
    if not _is_model(code_lines):
        return []
    known_array = df["array_typed"]
    out: List[dict] = []
    for i, raw in enumerate(code_lines):
        t = raw.lstrip()
        if t.startswith("//"):
            continue
        m = _WARN035_ASSIGN_RE.match(t.split("//", 1)[0])
        if not m:
            continue
        path = m.group(1)
        rhs = re.sub(r"[,;]\s*$", "", m.group(2).strip())
        if not rhs or rhs == "null" or "XDM_CONST." in rhs:
            continue
        if not xdm_path_is_array(path):
            continue
        if _rhs_is_array_typed(rhs, known_array):
            continue
        # Multi-line if(...arraycreate...) wrappers are common; defer when the
        # next few lines complete the array wrap.
        lookahead = " ".join(code_lines[i: i + 8])
        if re.search(r"\b(arraycreate|arrayconcat|arraymerge)\s*\(", lookahead) and re.search(
            r"\b(if|coalesce)\s*\(", rhs
        ):
            continue
        out.append(
            _violation(
                "WARN-035",
                "warning",
                i + 1,
                f"'{path}' is an Array-type XDM field but is assigned a "
                "scalar value. Wrap with arraycreate() or use an "
                "array-producing function so the shape matches the declared "
                "field.",
                f"Wrap the value: {path} = if(_value != null, "
                "arraycreate(_value), null).",
            )
        )
    return out


# ----- WARN-037  log-level word echoed into xdm.alert.severity


# A log-level word, only when it is the WHOLE quoted literal (so a value
# that merely contains "error", e.g. "Error Page Probe", is not flagged).
_LOG_LEVEL_VALUE_RE = re.compile(
    r'^"\s*(warning|warn|error|err|notice|debug)\s*"$', re.IGNORECASE
)
_SEVERITY_ASSIGN_START = re.compile(r"^\s*xdm\.alert\.severity\s*=(?!=)")
_ANY_ASSIGN_START = re.compile(r"^\s*(?:xdm\.[\w.]+|_[A-Za-z]\w*|[A-Za-z]\w*)\s*=(?!=)")
_FN_CALL_WRAP_RE = re.compile(r"^(if|coalesce)\s*\((.*)\)$", re.IGNORECASE | re.DOTALL)


def _depth_delta(text: str) -> int:
    """Net paren/bracket depth change for a line, string-aware."""
    d = 0
    for ch in _strip_strings(text):
        if ch in "([":
            d += 1
        elif ch in ")]":
            d -= 1
    return d


def _severity_value_log_levels(rhs: str) -> List[str]:
    """Log-level words used in VALUE positions of a severity RHS.

    A severity RHS is a direct literal, an ``if(cond, val, ..., default)``
    chain, or a ``coalesce(val, ...)``. Only the value positions matter:
    ``if(_level = "warning", ...)`` tests the vendor input (fine), whereas
    ``..., "Warning")`` echoes a log-level word into the band field (bad).
    Recurses into nested if() / coalesce() value branches.
    """
    rhs = re.sub(r"[,;]\s*$", "", rhs.strip()).strip()
    m = _FN_CALL_WRAP_RE.match(rhs)
    if m:
        fn = m.group(1).lower()
        args = _split_top_level_args(m.group(2))
        if fn == "coalesce":
            values = args
        else:  # if: values at odd indices, plus a trailing default if odd count
            values = [a for idx, a in enumerate(args) if idx % 2 == 1]
            if len(args) % 2 == 1 and args:
                values.append(args[-1])
        found: List[str] = []
        for v in values:
            found.extend(_severity_value_log_levels(v))
        return found
    mv = _LOG_LEVEL_VALUE_RE.match(rhs)
    return [mv.group(1)] if mv else []


def _check_warn037(code_lines: List[str]) -> List[dict]:
    """xdm.alert.severity is a band scale (Informational / Low / Medium /
    High / Critical), not a syslog level. A log-level word assigned to it
    -- directly or as an if-branch RESULT -- is a silent miscategorisation.
    Band it instead (see transformation-patterns.md log-level vocabulary).
    Comparison conditions (`_level = "warning"`) are the correct banding
    input and are not flagged."""
    out: List[dict] = []
    n = len(code_lines)
    i = 0
    while i < n:
        first = _strip_line_comment(code_lines[i])
        if _SEVERITY_ASSIGN_START.match(first):
            # Collect the assignment window: this line plus continuations,
            # tracking paren depth so an inner if() that spans several lines
            # is captured whole.
            window = [i]
            depth = _depth_delta(first)
            j = i + 1
            while j < n:
                cp = _strip_line_comment(code_lines[j])
                if not cp.strip():
                    j += 1
                    continue
                if depth <= 0 and (
                    _ANY_ASSIGN_START.match(cp)
                    or cp.lstrip().startswith("|")
                    or cp.strip() == ";"
                ):
                    break
                window.append(j)
                depth += _depth_delta(cp)
                j += 1
            rhs = "\n".join(_strip_line_comment(code_lines[k]) for k in window)
            rhs = re.sub(r"^\s*xdm\.alert\.severity\s*=", "", rhs, count=1)
            for word in _severity_value_log_levels(rhs):
                out.append(
                    _violation(
                        "WARN-037",
                        "warning",
                        i + 1,
                        f'xdm.alert.severity is assigned the log-level word '
                        f'"{word}". Severity is a band scale (Informational / '
                        "Low / Medium / High / Critical), not a syslog level, "
                        "so a log-level word there is a silent miscategorisation "
                        "downstream severity filters miss.",
                        "Band log-level vocabulary into proper severity bands "
                        "and map the raw level to xdm.event.log_level via "
                        "XDM_CONST.LOG_LEVEL_* -- see "
                        "references/transformation-patterns.md log-level "
                        "vocabulary.",
                    )
                )
            i = j
            continue
        i += 1
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

    df = _analyse_dataflow(code_lines)

    findings: List[dict] = []
    findings += _check_err009_010(code_lines)
    findings += _check_err011(code_lines)
    findings += _check_err012(code_lines, stage_of)
    findings += _check_err013(joined, line_starts)
    findings += _check_err014(code_lines, stage_of)
    findings += _check_err015(code_lines)
    findings += _check_err016(code_lines)
    findings += _check_err017(joined, code_lines, line_starts)
    findings += _check_err018(code_lines)
    findings += _check_err019(code_lines, df)
    findings += _check_err020(code_lines)
    findings += _check_err024(code_lines, stage_of, stage_start)
    findings += _check_err025(code_lines)
    findings += _check_err027(code_lines, stage_of, stage_start)
    findings += _check_warn014(code_lines)
    findings += _check_warn015(code_lines)
    findings += _check_warn017(code_lines)
    findings += _check_warn018(code_lines)
    findings += _check_warn035(code_lines, df)
    findings += _check_warn037(code_lines)

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
