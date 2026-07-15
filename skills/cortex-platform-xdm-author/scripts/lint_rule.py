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
    WARN-038 Host named (host.hostname) with a known ipv4 but no
             host.ipv4_addresses companion array.
    WARN-039 Whole payload (_raw_log / to_json_string) dumped into
             xdm.event.description instead of a concat() summary.
    WARN-040 Syslog header parsed with a vendor-anchored / positional
             regex instead of the PRI-anchored envelope idiom.
    WARN-041 Syslog priority captured but never decoded into
             xdm.event.log_level / xdm.alert.severity.
    WARN-042 Auto-detected authentication event missing a field from the
             authentication-story mandatory set (advisory, never blocks).
    WARN-043 Auto-detected network event missing a field from the
             network-story mandatory set (advisory, never blocks).
    WARN-044 Process / command-execution event mapping the executable to a
             parent-process field (advisory).
    WARN-045 xdm.event.tags assigned a value outside the closed six-member
             EVENT_TAG enum (advisory).
    WARN-046 Record-dropping content filter with no GOCORTEX_UNMODELLED
             catch-all sentinel (advisory).
    WARN-047 Prepend-fragile syslog extraction: a body field captured with
             a ^-anchored / positional regex instead of a payload token, so
             it misses the direct or relay-prepended arrival form (advisory).
    INFO-013 Advisory: one underscore temp mapped across 3+ XDM entity
             families (likely over-mapping; event / observer excluded).

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


# ----- WARN-038  missing host.ipv4_addresses companion


_HOST_SIDES = ("source", "target", "intermediate")


def _check_warn038(code_lines: List[str]) -> List[dict]:
    """When a host is named (`xdm.<side>.host.hostname`) and its IP is known
    (`xdm.<side>.ipv4`), the `xdm.<side>.host.ipv4_addresses` array companion
    should be populated too, so host-based correlation can pivot on either.
    A pure assignment-target check."""
    if not _is_model(code_lines):
        return []
    targets: dict = {}
    for i, raw in enumerate(code_lines):
        if raw.lstrip().startswith("//"):
            continue
        m = re.match(r"^\s*(xdm\.[\w.]+)\s*=(?!=)", raw.split("//", 1)[0])
        if m:
            targets.setdefault(m.group(1), i + 1)
    out: List[dict] = []
    for side in _HOST_SIDES:
        hostname = f"xdm.{side}.host.hostname"
        ipv4 = f"xdm.{side}.ipv4"
        arr = f"xdm.{side}.host.ipv4_addresses"
        if hostname in targets and ipv4 in targets and arr not in targets:
            out.append(
                _violation(
                    "WARN-038",
                    "warning",
                    targets[hostname],
                    f"{hostname} and {ipv4} are both set but the companion "
                    f"{arr} is missing. The host is named and its IP is known, "
                    "so populate the address array for host-based correlation.",
                    f"Add {arr} = if(<ip> != null, arraycreate(<ip>), null).",
                )
            )
    return out


# ----- INFO-013  over-mapping advisory (one temp across 3+ XDM families)


def _top_level_xdm_assignments(code_lines: List[str]) -> List[dict]:
    """Return [{path, line, rhs}] for each top-level `xdm.* =` assignment,
    capturing the full multi-line RHS window (paren-depth aware)."""
    cleaned = [_strip_line_comment(ln) for ln in code_lines]
    n = len(cleaned)
    out: List[dict] = []
    i = 0
    while i < n:
        cp = cleaned[i]
        m = re.match(r"^\s*(xdm\.[\w.]+)\s*=(?!=)", cp)
        if m:
            window = [i]
            depth = _depth_delta(cp)
            j = i + 1
            while j < n:
                c2 = cleaned[j]
                if not c2.strip():
                    j += 1
                    continue
                if depth <= 0 and (
                    _ANY_ASSIGN_START.match(c2)
                    or c2.lstrip().startswith("|")
                    or c2.strip() == ";"
                ):
                    break
                window.append(j)
                depth += _depth_delta(c2)
                j += 1
            rhs = "\n".join(cleaned[k] for k in window)
            rhs = re.sub(r"^\s*xdm\.[\w.]+\s*=", "", rhs, count=1)
            out.append({"path": m.group(1), "line": i + 1, "rhs": rhs})
            i = j
            continue
        i += 1
    return out


def _check_info013(code_lines: List[str]) -> List[dict]:
    """A single underscore temp consumed by xdm.* assignments across 3+
    distinct top-level XDM categories is usually over-mapping (forcing one
    value into unrelated field families). Advisory only -- the documented
    source<->target mirror (two categories) is excluded."""
    if not _is_model(code_lines):
        return []
    # `event` and `observer` are metadata sinks, not entity families:
    # xdm.event.description legitimately summarises many temps, and the
    # observer is the device, so neither counts toward over-mapping.
    metadata_cats = {"event", "observer"}
    temp_cats: dict = {}
    temp_line: dict = {}
    for a in _top_level_xdm_assignments(code_lines):
        parts = a["path"].split(".")
        cat = parts[1] if len(parts) > 1 else a["path"]
        if cat in metadata_cats:
            continue
        for m in _USCORE_TOKEN.finditer(a["rhs"]):
            name = m.group(1)
            temp_cats.setdefault(name, set()).add(cat)
            temp_line.setdefault(name, a["line"])
    out: List[dict] = []
    for name in sorted(temp_cats, key=lambda nm: temp_line[nm]):
        cats = temp_cats[name]
        if len(cats) >= 3 and cats != {"source", "target"}:
            cat_list = ", ".join("xdm." + c for c in sorted(cats))
            out.append(
                _violation(
                    "INFO-013",
                    "info",
                    temp_line[name],
                    f"Temp '{name}' is mapped across {len(cats)} XDM categories "
                    f"({cat_list}). Spreading one value over unrelated field "
                    "families is usually over-mapping -- confirm each target "
                    "genuinely holds this value.",
                    "Map the value only to the fields it truly belongs to. The "
                    "source <-> target mirror (two categories) is the one "
                    "routine multi-family case.",
                )
            )
    return out


# ----- WARN-039  raw payload dumped into xdm.event.description


def _check_warn039(code_lines: List[str]) -> List[dict]:
    """xdm.event.description is the analyst summary, not a payload sink.
    Assigning the whole ingested payload to it -- via `_raw_log` or by
    serialising an object with `to_json_string(...)` -- buries data that
    belongs in structured fields and defeats structured search. A correct
    description is a concat() over scalar temps and touches neither."""
    if not _is_model(code_lines):
        return []
    out: List[dict] = []
    for a in _top_level_xdm_assignments(code_lines):
        if a["path"] != "xdm.event.description":
            continue
        rhs = a["rhs"]
        if re.search(r"(?<![A-Za-z0-9_])_raw_log(?![A-Za-z0-9_])", rhs):
            trigger = "_raw_log"
        elif re.search(r"\bto_json_string\s*\(", rhs):
            trigger = "to_json_string(...)"
        else:
            continue
        out.append(
            _violation(
                "WARN-039",
                "warning",
                a["line"],
                f"xdm.event.description is assigned the whole payload via "
                f"{trigger}. The description is the analyst summary, not a "
                "payload sink -- dumping the raw log there buries data that "
                "belongs in structured fields and defeats structured search.",
                "Build the description with concat() over the identifying "
                "scalar fields, and map the rest of the payload to their own "
                "structured XDM homes. Never put _raw_log or to_json_string() "
                "in the description.",
            )
        )
    return out


# ----- WARN-040 / WARN-041  syslog envelope discipline


# A regextract(_raw_log, "PATTERN") call; group(1) is the raw pattern text
# with backslashes preserved. Header patterns sit on one physical line.
_REGEXTRACT_RAW_RE = re.compile(
    r'regextract\s*\(\s*_raw_log\s*,\s*"((?:\\.|[^"\\])*)"'
)

# A syslog positional timestamp header expressed as a regex: a month-name
# or RFC 5424 version token, a day number, then a clock. Matched against
# the pattern TEXT, so the metacharacters appear as literal backslash
# sequences. Tolerant of the common spellings ([A-Za-z]{3} or \w{3};
# \d+ or \d{1,2}; [\d:]+ or \d\d:\d\d).
_SYSLOG_HDR_SIG = re.compile(
    r"(?:\[A-Za-z\]\{3\}|\\w\{3\}|>\\w\+)"  # month name / 5424 version token
    r".{0,12}?\\d"                          # a day digit soon after
    r".{0,18}?"
    r"(?:\[\\d:\]|\\d\{1,2\}:\\d|\\d\\d:\\d|:\\d\{2\})"  # a clock fragment
)

# The PRI-capturing regextract is the only canonical pattern that opens a
# capture group immediately after the priority token: ^<(\d{1,3})>. The
# relay-aware variant skips a prepended relay/transport header with a
# greedy prefix and captures the innermost origin PRI: ^.*<(\d{1,3})>...
_PRI_CAPTURE_PREFIX = "^<("
_PRI_CAPTURE_PREFIX_RELAY = "^.*<("

# A syslog envelope capture opens either on the priority token (^<...) or
# behind a greedy relay-prefix (^.*...) that absorbs any prepended
# relay/transport header. Either way it is prepend-robust, so it must never
# be flagged as vendor-anchored (WARN-040) or prepend-fragile (WARN-047).
_ENVELOPE_ANCHOR_RE = re.compile(r"^\^(?:<|\.\*)")

# A greedy rest-of-line capture group -- (.*), (.+), (.*?) etc. Combined
# with a ^ anchor this is the "everything after the header" body grab that
# breaks the moment the header is absent (direct) or duplicated (relayed).
_GREEDY_REST_RE = re.compile(r"\(\.[*+]\??\)")


def _check_warn040(code_lines: List[str]) -> List[dict]:
    """A syslog header parsed with a vendor-anchored or positional regex
    instead of the PRI-anchored envelope idiom. Fires when a
    regextract(_raw_log, ...) pattern carries a syslog timestamp-header
    signature but is not anchored on the priority token (^<...). The
    canonical idiom in references/syslog-envelope.md always anchors on
    ^<\\d{1,3}>, so it is never flagged."""
    if not _is_model(code_lines):
        return []
    out: List[dict] = []
    for i, raw in enumerate(code_lines):
        cp = _strip_line_comment(raw)
        for m in _REGEXTRACT_RAW_RE.finditer(cp):
            pat = m.group(1)
            if _ENVELOPE_ANCHOR_RE.match(pat):
                # PRI-anchored, optionally behind a greedy relay-prefix.
                continue
            if not _SYSLOG_HDR_SIG.search(pat):
                continue
            out.append(
                _violation(
                    "WARN-040",
                    "warning",
                    i + 1,
                    "Syslog header parsed with a vendor-anchored or "
                    "positional regex. The header layout shifts between "
                    "sources, so this breaks on the next vendor and "
                    "discards the priority value entirely.",
                    "Anchor on the priority token instead: capture the host "
                    "with the RFC 3164 + RFC 5424 coalesce keyed on "
                    "^<\\d{1,3}> -- see references/syslog-envelope.md.",
                )
            )
    return out


def _check_warn041(code_lines: List[str]) -> List[dict]:
    """The syslog priority is captured but never decoded. Fires when a
    regextract anchors and captures the PRI (^<(\\d...)) yet the rule
    assigns neither xdm.event.log_level nor xdm.alert.severity anywhere.
    The priority is the one severity signal every syslog record carries;
    capturing it and dropping its severity wastes that floor."""
    if not _is_model(code_lines):
        return []
    pri_line = None
    for i, raw in enumerate(code_lines):
        cp = _strip_line_comment(raw)
        for m in _REGEXTRACT_RAW_RE.finditer(cp):
            pat = m.group(1)
            if pat.startswith(_PRI_CAPTURE_PREFIX) or pat.startswith(
                _PRI_CAPTURE_PREFIX_RELAY
            ):
                pri_line = i + 1
                break
        if pri_line is not None:
            break
    if pri_line is None:
        return []
    for raw in code_lines:
        cp = _strip_line_comment(raw)
        if re.match(
            r"\s*(?:xdm\.event\.log_level|xdm\.alert\.severity)\s*=(?!=)", cp
        ):
            return []
    return [
        _violation(
            "WARN-041",
            "warning",
            pri_line,
            "The syslog priority is captured but never decoded into "
            "xdm.event.log_level or xdm.alert.severity. The priority is the "
            "one severity signal every syslog record carries, so capturing "
            "it and dropping its severity loses that floor.",
            "Decode the priority (facility = PRI div 8, severity = PRI mod "
            "8) and use it as the fallback: coalesce(<payload severity>, "
            "_pri_sev_band) -- see references/syslog-envelope.md.",
        )
    ]


# ----- WARN-047  prepend-fragile syslog extraction (support both forms)


def _rule_is_syslog(code_lines: List[str]) -> bool:
    """True when the rule parses a syslog transport: it carries a
    PRI/envelope capture (^<... or ^.*<...) or a regextract pattern with a
    syslog timestamp-header signature. Used to gate WARN-047 so non-syslog
    shapes (CLF web access, CSV, JSON) are never touched."""
    for raw in code_lines:
        cp = _strip_line_comment(raw)
        for m in _REGEXTRACT_RAW_RE.finditer(cp):
            pat = m.group(1)
            if _ENVELOPE_ANCHOR_RE.match(pat) or _SYSLOG_HDR_SIG.search(pat):
                return True
    return False


def _check_warn047(code_lines: List[str]) -> List[dict]:
    """A syslog body field extracted with a ^-anchored / positional regex.

    Syslog rarely arrives byte-for-byte as the device emits it: bounced
    through an intermediate relay the line gains a prepended
    ``<PRI> ts host tag:`` header (sometimes two), and direct off the box
    it may have none. A ^-anchored body capture assumes a fixed prefix, so
    it silently misses every record whose arrival form differs from the
    build-time sample. The hard rule for syslog: anchor each field on its
    own payload token (position-independent regextract), and let the
    relay-aware Stage 0 (^.*<) own the envelope. Fires only in a syslog
    rule, and only on a ^-anchored _raw_log capture that is neither a
    sanctioned envelope capture (^<... / ^.*<...) nor -- when it is the
    envelope prefix -- an "everything after the header" grab ((.*)/(.+))."""
    if not _is_model(code_lines):
        return []
    if not _rule_is_syslog(code_lines):
        return []
    out: List[dict] = []
    for i, raw in enumerate(code_lines):
        cp = _strip_line_comment(raw)
        for m in _REGEXTRACT_RAW_RE.finditer(cp):
            pat = m.group(1)
            if not pat.startswith("^"):
                continue  # token-anchored -> position independent, fine
            # An envelope capture is prepend-robust (^< / ^.*) or is a
            # header field (host / tag, carries a timestamp-header
            # signature) -- the latter is WARN-040's domain, not ours.
            envelope = bool(
                _ENVELOPE_ANCHOR_RE.match(pat) or _SYSLOG_HDR_SIG.search(pat)
            )
            greedy_rest = bool(_GREEDY_REST_RE.search(pat))
            if envelope and not greedy_rest:
                continue  # sanctioned host / PRI / tag envelope capture
            out.append(
                _violation(
                    "WARN-047",
                    "warning",
                    i + 1,
                    "Prepend-fragile syslog extraction: a body field is "
                    "captured with a ^-anchored / positional regex (or an "
                    "'everything after the header' grab). The same source "
                    "arrives direct off the box and behind a relay-prepended "
                    "<PRI> header, so a fixed-prefix anchor misses whichever "
                    "form the build sample did not show.",
                    "Anchor on the payload's own token instead (e.g. "
                    "regextract(_raw_log, \"key=([^\\s]+)\") or the "
                    "%FAC-SEV-MNEMONIC token) so extraction is identical for "
                    "both forms; leave the envelope to the relay-aware Stage "
                    "0 (^.*<) -- see references/syslog-envelope.md.",
                )
            )
    return out


# ----- WARN-042  authentication-story mandatory mapping (auto-detected)


_AUTH_MANDATORY = [
    "xdm.source.ipv4",
    "xdm.source.port",
    "xdm.target.ipv4",
    "xdm.target.port",
    "xdm.network.ip_protocol",
    "xdm.event.type",
    "xdm.event.tags",
    "xdm.event.operation",
    "xdm.event.original_event_type",
    "xdm.event.outcome",
    "xdm.auth.service",
    "xdm.source.user.upn",
    "xdm.source.user.identity_type",
    "xdm.source.user.user_type",
]

_AUTH_FIELD_HINT = {
    "xdm.source.ipv4": "map the real client address from the raw log "
    "(never a static value, list, or empty string)",
    "xdm.source.port": "map the value, else xdm.source.port = to_integer(0)",
    "xdm.target.ipv4": 'map the value, else xdm.target.ipv4 = "" '
    "(string here, never a list)",
    "xdm.target.port": "map the value, else xdm.target.port = to_integer(0)",
    "xdm.network.ip_protocol": "assign XDM_CONST.IP_PROTOCOL_* "
    "(pad IP_PROTOCOL_IP when the protocol is absent)",
    "xdm.event.type": 'resolve to a value containing "authentication"',
    "xdm.event.tags": "xdm.event.tags = "
    "arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION)",
    "xdm.event.operation": "derive the specific XDM_CONST.OPERATION_TYPE_* "
    "(AUTH_LOGIN for a password login, AUTH_MFA for MFA); leave unmapped "
    "rather than guessing when the event kind is unclear",
    "xdm.event.original_event_type": "carry the raw vendor event name",
    "xdm.event.outcome": "XDM_CONST.OUTCOME_SUCCESS / OUTCOME_FAILED only, "
    "on conclusive events",
    "xdm.auth.service": "the authentication service name (Kerberos / "
    "NTLM / OAuth2 / SAML / SSO / RADIUS / TACACS+ / LDAP); normalise the "
    'vendor protocol field, pad "Login" when absent',
    "xdm.source.user.upn": "the authenticated identity in UPN format "
    "(the authentication-story correlation key)",
    "xdm.source.user.identity_type": "derive the XDM_CONST.IDENTITY_TYPE_* "
    "member (IDENTITY_TYPE_USER for a human principal -- the common case; "
    "MACHINE / BUILTIN / VIRTUAL per the principal); pad "
    "XDM_CONST.IDENTITY_TYPE_UNKNOWN",
    "xdm.source.user.user_type": "always derive the XDM_CONST.USER_TYPE_* "
    "member: USER_TYPE_MACHINE_ACCOUNT for a $-suffixed account, "
    "USER_TYPE_SERVICE_ACCOUNT for a svc_/service/gserviceaccount name, "
    "else USER_TYPE_REGULAR (the default)",
}

_AUTH_OPERATION_RE = re.compile(r"OPERATION_TYPE_AUTH_\w+")

# Broader event-signal vocabulary, mirroring profile_log.py's
# _AUTH_VALUE_RE. A rule can model an authentication event without ever
# using an explicit XDM auth marker (EVENT_TAG_AUTHENTICATION,
# OPERATION_TYPE_AUTH_*, or the word "authentication" in event.type) --
# e.g. xdm.event.original_event_type = "user.login". When an
# event-classification field carries such a literal, WARN-042 must still
# classify the rule as authentication so the mandatory-field checklist
# applies. Word-ish boundaries (allowing a leading "_"/"-"/".") keep the
# tokens from matching inside unrelated words while still firing on
# "user.login" and "ssh_user_login".
_AUTH_LITERAL_RE = re.compile(
    r"(?<![a-z0-9])("
    r"logon|logoff|login|logout|logged[ _-]?in|logged[ _-]?out|"
    r"sign[ _-]?in|sign[ _-]?on|signin|signon|"
    r"authentication|authenticated|"
    r"mfa|multi-factor|two-factor|2fa|otp|sso|saml|kerberos|"
    r"password|credential"
    r")(?![a-z0-9])",
    re.IGNORECASE,
)

# The event-classification fields whose literal values carry event
# semantics. Only these are scanned for the broader auth literal signal,
# to keep classification conservative (an auth token in, say, a hostname
# or username field must not flip a rule to "authentication").
_AUTH_SIGNAL_FIELDS = (
    "xdm.event.type",
    "xdm.event.original_event_type",
    "xdm.event.operation",
)

# Value-conformance vocabularies. A mandatory authentication field that is
# present but assigned a value the authentication story forbids is as
# damaging as leaving it unmapped, so WARN-042 also checks the value when
# it can do so with certainty.
_AUTH_ANY_OPERATION_RE = re.compile(r"OPERATION_TYPE_[A-Z_]+")
_AUTH_OUTCOME_RE = re.compile(r"OUTCOME_[A-Z_]+")
_AUTH_OUTCOME_OK = {"OUTCOME_SUCCESS", "OUTCOME_FAILED"}
# xdm.auth.service is a free-string service NAME, so there is no allowed
# vocabulary to enforce. The only definite error is the deprecated
# "SP"/"IDP" role token from the retired v1 guidance -- flagged so old
# rules are migrated to a real service name.
_AUTH_SERVICE_DEPRECATED = {"SP", "IDP"}


def _rhs_has_dynamic(rhs: str) -> bool:
    """True when the RHS can resolve to a value the linter cannot see
    statically: a temp reference, an xdm.* read, an XDM_CONST.*, or any
    function call. Used to suppress value-conformance flags on anything
    that is not a self-contained literal -- the linter must never guess a
    temp's or expression's runtime value."""
    if "XDM_CONST." in rhs:
        return True
    if re.search(r"[A-Za-z_]\w*\s*\(", rhs):  # function call e.g. if(, concat(
        return True
    if re.search(r"(?<![\w.])_[A-Za-z]\w*", rhs):  # temp reference
        return True
    if re.search(r"\bxdm\.", rhs):  # reads another xdm field
        return True
    return False


def _rhs_is_static_literal(rhs: str) -> bool:
    """True only when the RHS is a self-contained static literal: a single
    quoted string (including the empty string) or a bare number. A bare
    identifier is a raw-column reference, not a literal, so it returns
    False -- the linter must never mistake a direct-column mapping
    (xdm.source.ipv4 = src_ip) for a hard-coded value."""
    body = rhs.strip().rstrip(",").strip()
    if not body:
        return False
    if re.fullmatch(r'"[^"]*"', body):
        return True
    if re.fullmatch(r"-?\d+(?:\.\d+)?", body):
        return True
    return False


def _auth_value_issues(path: str, rhs: str) -> List[tuple]:
    """Return [(message, suggestion)] for a mapped mandatory auth field
    whose value violates the closed vocabulary the authentication story
    demands. Conservative on purpose: only a definitively wrong,
    self-contained literal is flagged. Anything sourced from a temp, an
    xdm read, an XDM_CONST expression, or a function call is left alone so
    that legitimate runtime-resolved mappings never false-fire."""
    issues: List[tuple] = []
    lits = re.findall(r'"([^"]*)"', rhs)

    if path == "xdm.source.ipv4":
        if _rhs_is_static_literal(rhs):
            issues.append((
                "This rule models an authentication event, but "
                "xdm.source.ipv4 is assigned a static literal. The source "
                "address must be mapped from the raw log (never a static "
                "value, list, or empty string), or the authentication "
                "story cannot correlate the client.",
                "Map the real client address from the raw log.",
            ))
    elif path == "xdm.source.user.upn":
        if _rhs_is_static_literal(rhs):
            issues.append((
                "This rule models an authentication event, but "
                "xdm.source.user.upn is assigned a static literal. The upn "
                "is the story correlation key and cannot be empty or "
                "hard-coded -- it must carry the authenticated identity "
                "from the raw log.",
                "Derive the upn from the raw principal with the shape "
                'guard: if(_u contains "@", _u, _u != null, '
                'concat(_u, "@localhost")).',
            ))
        else:
            # The upn must ALWAYS be UPN-shaped. A bare identifier is only
            # acceptable when its own name says the source is a UPN
            # (upn / userPrincipalName / principal / email / mail /
            # alternateId); any other bare username must go through the
            # shape-guard idiom.
            body = rhs.strip().rstrip(",").strip()
            m = re.fullmatch(r"_?[A-Za-z]\w*", body)
            if m and body.lower() not in ("null", "true", "false"):
                name = body.lower()
                if not any(t in name for t in
                           ("upn", "principal", "email", "mail",
                            "alternateid", "alternate_id")):
                    issues.append((
                        "This rule models an authentication event, but "
                        f"xdm.source.user.upn is assigned the bare "
                        f"identifier '{body}', which may not be UPN-shaped. "
                        "The upn must ALWAYS be user@domain.",
                        "Use the shape guard: xdm.source.user.upn = "
                        f'if({body} contains "@", {body}, {body} != null, '
                        f'concat({body}, "@localhost")). A direct mapping '
                        "is only safe when the source field is a UPN by "
                        "definition (see authentication-mapping.md).",
                    ))
    elif path == "xdm.target.ipv4":
        if "arraycreate(" in rhs or re.match(r"\s*\[", rhs):
            issues.append((
                "This rule models an authentication event, but "
                "xdm.target.ipv4 is assigned a list. This field is a single "
                "string, not an array.",
                'Map a single value, else xdm.target.ipv4 = "".',
            ))
    elif path == "xdm.network.ip_protocol":
        if "IP_PROTOCOL_" not in rhs and _rhs_is_static_literal(rhs):
            issues.append((
                "This rule models an authentication event, but "
                "xdm.network.ip_protocol is assigned a raw literal instead "
                "of the XDM enum.",
                "Assign XDM_CONST.IP_PROTOCOL_* "
                "(IP_PROTOCOL_TCP for interactive auth).",
            ))
    elif path == "xdm.source.user.identity_type":
        if "IDENTITY_TYPE_" not in rhs and _rhs_is_static_literal(rhs):
            issues.append((
                "This rule models an authentication event, but "
                "xdm.source.user.identity_type is assigned a raw literal "
                "instead of the XDM enum.",
                "Assign XDM_CONST.IDENTITY_TYPE_* "
                "(IDENTITY_TYPE_USER for a human principal; "
                "IDENTITY_TYPE_UNKNOWN as the fall-back).",
            ))
    elif path == "xdm.source.user.user_type":
        if "USER_TYPE_" not in rhs and _rhs_is_static_literal(rhs):
            issues.append((
                "This rule models an authentication event, but "
                "xdm.source.user.user_type is assigned a raw literal "
                "instead of the XDM enum.",
                "Assign XDM_CONST.USER_TYPE_* "
                "(USER_TYPE_REGULAR as the default; MACHINE_ACCOUNT / "
                "SERVICE_ACCOUNT per the principal).",
            ))
    elif path == "xdm.event.type":
        if lits and not _rhs_has_dynamic(rhs) and not any(
            "authentication" in s.lower() for s in lits
        ):
            issues.append((
                "This rule models an authentication event, but "
                'xdm.event.type does not resolve to a value containing '
                '"authentication", which the authentication story keys on.',
                'Resolve xdm.event.type to a value containing '
                '"authentication".',
            ))
    elif path == "xdm.event.tags":
        if "EVENT_TAG_" in rhs and "EVENT_TAG_AUTHENTICATION" not in rhs:
            issues.append((
                "This rule models an authentication event, but "
                "xdm.event.tags enumerates tag constants without "
                "XDM_CONST.EVENT_TAG_AUTHENTICATION, the story marker tag.",
                "xdm.event.tags = "
                "arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION).",
            ))
    elif path == "xdm.event.operation":
        ops = _AUTH_ANY_OPERATION_RE.findall(rhs)
        if ops and not any(o.startswith("OPERATION_TYPE_AUTH") for o in ops):
            issues.append((
                "This rule models an authentication event, but "
                "xdm.event.operation is a non-authentication operation.",
                "Use XDM_CONST.OPERATION_TYPE_AUTH_LOGIN (password) or "
                "OPERATION_TYPE_AUTH_MFA (involves MFA).",
            ))
    elif path == "xdm.event.outcome":
        bad = sorted(
            {o for o in _AUTH_OUTCOME_RE.findall(rhs) if o not in _AUTH_OUTCOME_OK}
        )
        if bad:
            issues.append((
                "This rule models an authentication event, but "
                f"xdm.event.outcome uses {', '.join(bad)}. The "
                "authentication story supports OUTCOME_SUCCESS / "
                "OUTCOME_FAILED only.",
                "Use XDM_CONST.OUTCOME_SUCCESS or OUTCOME_FAILED, on "
                "conclusive events only.",
            ))
    elif path == "xdm.auth.service":
        # xdm.auth.service is the authentication service NAME (a free
        # String: Kerberos, NTLM, OAuth2, SSO, ...), not a role. The only
        # value error we can be certain of is the deprecated "SP"/"IDP"
        # role token from the retired v1 guidance -- flag it so old rules
        # get migrated. Any other free-string service name is accepted.
        if _rhs_is_static_literal(rhs):
            body = rhs.strip().rstrip(",").strip()
            if body.strip('"').upper() in _AUTH_SERVICE_DEPRECATED:
                issues.append((
                    "This rule models an authentication event, but "
                    "xdm.auth.service is the deprecated SP/IDP role token. "
                    "xdm.auth.service is the authentication service NAME "
                    "(a free String), not a role.",
                    "Map the authentication service name from the vendor "
                    "protocol field (Kerberos / NTLM / OAuth2 / SAML / SSO "
                    '/ RADIUS / TACACS+ / LDAP), or pad "Login".',
                ))
    return issues


def _check_warn042(code_lines: List[str]) -> List[dict]:
    """Auto-detect an authentication event and warn (never block) when a
    field in the authoritative authentication-story mandatory set is not
    mapped. A rule is treated as an authentication rule when it carries a
    definitive auth marker -- the EVENT_TAG_AUTHENTICATION tag on
    xdm.event.tags, an OPERATION_TYPE_AUTH_* operation on
    xdm.event.operation, or an xdm.event.type value containing
    "authentication" -- OR a broader auth literal (login, logon, signin,
    mfa, sso, ...) in an event-classification field such as
    xdm.event.original_event_type = "user.login", so a rule that models
    authentication without ever using an explicit XDM marker is still
    classified. When a marker is found, every missing mandatory field is
    reported at the marker line,
    and every mapped mandatory field whose value violates the closed
    vocabulary the authentication story demands (the wrong const, a static
    source address, a list where a string is required, and so on) is
    reported at its own line. Advisory only (warning severity), so the
    exit code stays 0. Value conformance is conservative: only a
    definitively wrong, self-contained literal is flagged -- temps, xdm
    reads and const expressions are never second-guessed. See
    references/authentication-mapping.md."""
    if not _is_model(code_lines):
        return []
    assigns = _top_level_xdm_assignments(code_lines)
    targets = {a["path"]: a["line"] for a in assigns}
    rhs_by_path = {a["path"]: a["rhs"] for a in assigns}
    marker_line = None
    for a in assigns:
        path, rhs = a["path"], a["rhs"]
        if path == "xdm.event.tags" and "EVENT_TAG_AUTHENTICATION" in rhs:
            marker_line = a["line"]
            break
        if path == "xdm.event.operation" and _AUTH_OPERATION_RE.search(rhs):
            marker_line = a["line"]
            break
        # Marker words are matched against QUOTED LITERALS only -- a temp
        # named _authentication_kind on the RHS must not classify the rule.
        if path == "xdm.event.type" and any(
            "authentication" in lit.lower()
            for lit in re.findall(r'"([^"]*)"', rhs)
        ):
            marker_line = a["line"]
            break
        # Broader event signal: an auth literal in an event-classification
        # field (e.g. xdm.event.original_event_type = "user.login") models
        # an authentication event even without an explicit XDM auth marker.
        if path in _AUTH_SIGNAL_FIELDS:
            if any(_AUTH_LITERAL_RE.search(lit) for lit in re.findall(r'"([^"]*)"', rhs)):
                marker_line = a["line"]
                break
    if marker_line is None:
        return []
    out: List[dict] = []
    for field in _AUTH_MANDATORY:
        if field in targets:
            continue
        out.append(
            _violation(
                "WARN-042",
                "warning",
                marker_line,
                f"This rule models an authentication event, so {field} is "
                "mandatory for the XDM authentication story but is not "
                "mapped. A mandatory field left unmapped drops the event "
                "from the story and from identity analytics.",
                f"Map {field}: {_AUTH_FIELD_HINT[field]} "
                "(see references/authentication-mapping.md).",
            )
        )
    # A second xdm.event.tags assignment silently overwrites the first,
    # dropping its story tag. Reported here for auth-marked rules; when
    # the NETWORK marker is also present, WARN-043 owns the finding, so
    # skip it to avoid double-reporting on a dual rule.
    tags_assigns = [a for a in assigns if a["path"] == "xdm.event.tags"]
    network_marked = any(
        "EVENT_TAG_NETWORK" in a["rhs"] for a in tags_assigns
    )
    if len(tags_assigns) > 1 and not network_marked:
        out.append(
            _violation(
                "WARN-042",
                "warning",
                tags_assigns[1]["line"],
                "xdm.event.tags is assigned more than once; the later "
                "assignment overwrites the earlier one, dropping its story "
                "tag.",
                "Emit ONE merged xdm.event.tags = arraycreate(...) carrying "
                "every story tag.",
            )
        )
    # Value conformance: a mandatory field that is mapped but carries a
    # forbidden value is as damaging as one left unmapped.
    for field in _AUTH_MANDATORY:
        if field not in rhs_by_path:
            continue
        for msg, fix in _auth_value_issues(field, rhs_by_path[field]):
            out.append(
                _violation(
                    "WARN-042",
                    "warning",
                    targets[field],
                    f"{msg} (see references/authentication-mapping.md).",
                    fix,
                )
            )
    return out


# ----- WARN-043  network-story mandatory mapping (auto-detected)


# Mandatory XDM target set for the network story. Canonical in-bundle
# source: the "Mandatory fields" table in references/network-mapping.md
# (mirrored in profile_log.py; the drift-guard test keeps all three
# aligned).
_NETWORK_MANDATORY = [
    "xdm.event.outcome",
    "xdm.event.type",
    "xdm.event.tags",
    "xdm.network.http.http_header.header",
    "xdm.network.http.http_header.value",
    "xdm.network.http.url_category",
    "xdm.network.ip_protocol",
    "xdm.network.protocol_layers",
    "xdm.source.host.device_id",
    "xdm.source.ipv4",
    "xdm.source.ipv6",
    "xdm.source.is_internal_ip",
    "xdm.source.port",
    "xdm.source.sent_bytes",
    "xdm.target.host.device_id",
    "xdm.target.ipv4",
    "xdm.target.ipv6",
    "xdm.target.is_internal_ip",
    "xdm.target.port",
    "xdm.target.sent_bytes",
]

_NETWORK_FIELD_HINT = {
    "xdm.event.outcome": "map allow -> OUTCOME_SUCCESS, deny/drop/block -> "
    "OUTCOME_FAILED; pad XDM_CONST.OUTCOME_UNKNOWN",
    "xdm.event.type": 'resolve to a value containing "network"; pad '
    '"network"',
    "xdm.event.tags": "xdm.event.tags = "
    "arraycreate(XDM_CONST.EVENT_TAG_NETWORK) -- one merged arraycreate "
    "with EVENT_TAG_AUTHENTICATION on a dual event",
    "xdm.network.http.http_header.header": 'the HTTP header name; map when '
    'headers are logged, else ""',
    "xdm.network.http.http_header.value": 'the HTTP header value; map when '
    'headers are logged, else ""',
    "xdm.network.http.url_category": "map via an XDM_CONST.URL_CATEGORY_* "
    "if-chain; pad XDM_CONST.URL_CATEGORY_UNKNOWN",
    "xdm.network.ip_protocol": "assign XDM_CONST.IP_PROTOCOL_*; pad "
    "XDM_CONST.IP_PROTOCOL_IP",
    "xdm.network.protocol_layers": "arraycreate(...) over the known layers "
    '(highest last); pure pad arraycreate("IP")',
    "xdm.source.host.device_id": 'map the client device id, else ""',
    "xdm.source.ipv4": 'map the observed client address; pad "" only when '
    "the source is IPv6-only",
    "xdm.source.ipv6": 'map the observed client address; pad "" when '
    "IPv4-only",
    "xdm.source.is_internal_ip": "derive via incidr() over RFC 1918; pure "
    "pad false",
    "xdm.source.port": "map the value, else xdm.source.port = to_integer(0)",
    "xdm.source.sent_bytes": "bytes sent by the source, else to_integer(0)",
    "xdm.target.host.device_id": 'map when known, else ""',
    "xdm.target.ipv4": 'map the observed address; pad ""',
    "xdm.target.ipv6": 'map the observed address; pad ""',
    "xdm.target.is_internal_ip": "derive via incidr() over RFC 1918; pure "
    "pad false",
    "xdm.target.port": "map the value, else xdm.target.port = to_integer(0)",
    "xdm.target.sent_bytes": "bytes sent by the target, else to_integer(0)",
}

# Network outcome vocabulary: the padding value OUTCOME_UNKNOWN is legal
# here (unlike the authentication story, which is SUCCESS / FAILED only).
_NETWORK_OUTCOME_OK = {"OUTCOME_SUCCESS", "OUTCOME_FAILED", "OUTCOME_UNKNOWN"}


def _network_value_issues(path: str, rhs: str) -> List[tuple]:
    """Return [(message, suggestion)] for a mapped mandatory network field
    whose value violates what the network story demands. Same conservatism
    as the authentication twin: only a definitively wrong, self-contained
    construct is flagged; temps, xdm reads, const expressions and function
    calls are never second-guessed."""
    issues: List[tuple] = []
    lits = re.findall(r'"([^"]*)"', rhs)

    if path == "xdm.event.tags":
        if "EVENT_TAG_" in rhs and "EVENT_TAG_NETWORK" not in rhs:
            issues.append((
                "This rule models a network event, but xdm.event.tags "
                "enumerates tag constants without "
                "XDM_CONST.EVENT_TAG_NETWORK, the story marker tag.",
                "Include XDM_CONST.EVENT_TAG_NETWORK in the single "
                "arraycreate(...) (alongside EVENT_TAG_AUTHENTICATION on a "
                "dual event).",
            ))
    elif path == "xdm.network.ip_protocol":
        if "IP_PROTOCOL_" not in rhs and _rhs_is_static_literal(rhs):
            issues.append((
                "This rule models a network event, but "
                "xdm.network.ip_protocol is assigned a raw literal instead "
                "of the XDM enum.",
                "Assign XDM_CONST.IP_PROTOCOL_*; the padding value is "
                "IP_PROTOCOL_TCP.",
            ))
    elif path == "xdm.network.protocol_layers":
        if "arraycreate(" not in rhs and _rhs_is_static_literal(rhs):
            issues.append((
                "This rule models a network event, but "
                "xdm.network.protocol_layers is assigned a bare scalar. "
                "Content packs emit this field as an array of layers.",
                "Wrap the layers in arraycreate(...), highest layer last; "
                'the pure pad is arraycreate("TCP").',
            ))
    elif path == "xdm.event.outcome":
        bad = sorted(
            {o for o in _AUTH_OUTCOME_RE.findall(rhs)
             if o not in _NETWORK_OUTCOME_OK}
        )
        if bad:
            issues.append((
                "This rule models a network event, but xdm.event.outcome "
                f"uses {', '.join(bad)}. The network story supports "
                "OUTCOME_SUCCESS / OUTCOME_FAILED, with OUTCOME_UNKNOWN as "
                "the padding value.",
                "Map allow -> OUTCOME_SUCCESS, deny/drop/block -> "
                "OUTCOME_FAILED; pad OUTCOME_UNKNOWN.",
            ))
    elif path == "xdm.event.type":
        # On a dual event the single event.type string carries the
        # authentication value and the tags array carries the network
        # marker, so an "authentication" literal is also acceptable.
        if lits and not _rhs_has_dynamic(rhs) and not any(
            ("network" in s.lower()) or ("authentication" in s.lower())
            for s in lits
        ):
            issues.append((
                "This rule models a network event, but xdm.event.type does "
                'not resolve to a value containing "network" (or the '
                "authentication value on a dual event).",
                'Resolve xdm.event.type to a value containing "network"; '
                "on a dual event keep the authentication value and carry "
                "the network marker in xdm.event.tags.",
            ))
    return issues


def _check_warn043(code_lines: List[str]) -> List[dict]:
    """Auto-detect a network event and warn (never block) when a field in
    the authoritative network-story mandatory set is not mapped. Detection
    is deliberately conservative -- transport fields alone never classify a
    rule -- so a rule is treated as a network rule only on a definitive
    marker: the EVENT_TAG_NETWORK tag on xdm.event.tags, or an
    xdm.event.type value containing "network". When a marker is found,
    every missing mandatory field is reported at the marker line, a
    duplicated xdm.event.tags assignment is flagged (the second overwrites
    the first -- a dual event needs ONE merged arraycreate), and every
    mapped mandatory field whose value violates the network vocabulary is
    reported at its own line, with the same only-definitive-literals
    conservatism as WARN-042. Advisory only (warning severity), so the
    exit code stays 0. Independent of WARN-042: a dual authentication +
    network rule receives both advisories. See
    references/network-mapping.md."""
    if not _is_model(code_lines):
        return []
    assigns = _top_level_xdm_assignments(code_lines)
    targets = {a["path"]: a["line"] for a in assigns}
    rhs_by_path = {a["path"]: a["rhs"] for a in assigns}
    marker_line = None
    for a in assigns:
        path, rhs = a["path"], a["rhs"]
        if path == "xdm.event.tags" and "EVENT_TAG_NETWORK" in rhs:
            marker_line = a["line"]
            break
        # Quoted literals only -- a temp named _network_type on the RHS
        # must not classify the rule as a network event.
        if path == "xdm.event.type" and any(
            "network" in lit.lower()
            for lit in re.findall(r'"([^"]*)"', rhs)
        ):
            marker_line = a["line"]
            break
    if marker_line is None:
        return []
    out: List[dict] = []
    for field in _NETWORK_MANDATORY:
        if field in targets:
            continue
        out.append(
            _violation(
                "WARN-043",
                "warning",
                marker_line,
                f"This rule models a network event, so {field} is mandatory "
                "for the XDM network story but is not mapped. A mandatory "
                "field left unmapped drops the event from the story.",
                f"Map {field}: {_NETWORK_FIELD_HINT[field]} "
                "(see references/network-mapping.md).",
            )
        )
    # A dual event must merge its story tags into ONE arraycreate; a second
    # xdm.event.tags assignment silently overwrites the first.
    tags_assigns = [a for a in assigns if a["path"] == "xdm.event.tags"]
    if len(tags_assigns) > 1:
        out.append(
            _violation(
                "WARN-043",
                "warning",
                tags_assigns[1]["line"],
                "xdm.event.tags is assigned more than once; the later "
                "assignment overwrites the earlier one, dropping its story "
                "tag.",
                "Emit ONE merged xdm.event.tags = arraycreate(...) carrying "
                "every story tag (for a dual event: "
                "EVENT_TAG_AUTHENTICATION and EVENT_TAG_NETWORK).",
            )
        )
    # Value conformance: a mandatory field mapped to a forbidden value is
    # as damaging as one left unmapped.
    for field in _NETWORK_MANDATORY:
        if field not in rhs_by_path:
            continue
        for msg, fix in _network_value_issues(field, rhs_by_path[field]):
            out.append(
                _violation(
                    "WARN-043",
                    "warning",
                    targets[field],
                    f"{msg} (see references/network-mapping.md).",
                    fix,
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


# ----- WARN-044  process / command-execution advisory

# Recommended (NOT mandatory) process fields -- XDM has no process story
# tag, so there is no mandatory gate. Mirrors _PROCESS_RECOMMENDED in
# profile_log.py. See references/process-mapping.md.
_PROCESS_RECOMMENDED = [
    "xdm.source.process.name",
    "xdm.source.process.command_line",
    "xdm.source.process.pid",
    "xdm.source.process.executable.path",
]

# The executable parent node is typed Number in the schema (it is a
# container, not the image name). Assigning a value to it -- instead of a
# leaf such as executable.path / executable.filename -- silently mistypes
# the field. This is the one high-signal, zero-ambiguity process error.
_PROCESS_EXECUTABLE_PARENT_RE = re.compile(
    r"^xdm\.(?:source|target|intermediate)\.process\.executable$"
)


def _check_warn044(code_lines: List[str]) -> List[dict]:
    """Advisory for process / command-execution mappings. Flags a value
    assigned to the xdm.*.process.executable parent (a Number container),
    which mistypes the field -- the image name belongs on a leaf
    (executable.path / executable.filename). Advisory only (warning
    severity), so the exit code stays 0. See
    references/process-mapping.md."""
    if not _is_model(code_lines):
        return []
    out: List[dict] = []
    for a in _top_level_xdm_assignments(code_lines):
        if _PROCESS_EXECUTABLE_PARENT_RE.match(a["path"]):
            out.append(
                _violation(
                    "WARN-044",
                    "warning",
                    a["line"],
                    f"{a['path']} is the executable parent node (typed "
                    "Number in the schema), not the image name, so this "
                    "assignment mistypes the field.",
                    "Map a leaf instead: <side>.process.executable.path or "
                    "executable.filename (see references/process-mapping.md).",
                )
            )
    return out


# ----- WARN-045  event.tags conformance to the closed EVENT_TAG enum

# xdm.event.tags is a CLOSED six-member enum. Any other EVENT_TAG_* token
# is invented and mistypes the field. See references/xdm-const.md.
_VALID_EVENT_TAGS = {
    "EVENT_TAG_AUTHENTICATION",
    "EVENT_TAG_NETWORK",
    "EVENT_TAG_CLOUD",
    "EVENT_TAG_SAAS",
    "EVENT_TAG_ONPREM",
    "EVENT_TAG_VPN",
}
_EVENT_TAG_TOKEN_RE = re.compile(r"EVENT_TAG_[A-Z0-9_]+")


def _check_warn045(code_lines: List[str]) -> List[dict]:
    """Flag any EVENT_TAG_* token in an xdm.event.tags assignment that is
    not a member of the closed six-member EVENT_TAG enum (AUTHENTICATION,
    NETWORK, CLOUD, SAAS, ONPREM, VPN). An invented tag mistypes the
    field. Advisory only (warning severity), so the exit code stays 0. See
    references/xdm-const.md."""
    if not _is_model(code_lines):
        return []
    out: List[dict] = []
    for a in _top_level_xdm_assignments(code_lines):
        if a["path"] != "xdm.event.tags":
            continue
        bad = sorted(
            {
                t
                for t in _EVENT_TAG_TOKEN_RE.findall(a["rhs"])
                if t not in _VALID_EVENT_TAGS
            }
        )
        if bad:
            out.append(
                _violation(
                    "WARN-045",
                    "warning",
                    a["line"],
                    "xdm.event.tags uses "
                    + ", ".join(bad)
                    + ", which is not a member of the closed EVENT_TAG enum.",
                    "Use only XDM_CONST.EVENT_TAG_AUTHENTICATION / "
                    "EVENT_TAG_NETWORK / EVENT_TAG_CLOUD / EVENT_TAG_SAAS / "
                    "EVENT_TAG_ONPREM / EVENT_TAG_VPN "
                    "(see references/xdm-const.md).",
                )
            )
    return out


# ----- WARN-046  record-dropping content filter without a catch-all

# The only filter that does not shrink the datamodel row count is the
# `_raw_log != null` guard (it drops only empty records). Any other filter
# predicate narrows by content, so a `datamodel` search returns fewer rows
# than the raw dataset -- unless the rule instead classifies per record and
# gives the unmatched records the catch-all sentinel. See
# references/record-classification.md.
_CATCHALL_SENTINEL = "GOCORTEX_UNMODELLED"
_NULL_GUARD_RE = re.compile(r"_raw_log\s*!=\s*null", re.IGNORECASE)


def _check_warn046(code_lines: List[str]) -> List[dict]:
    """Advisory when a MODEL rule narrows records with a content filter
    (anything beyond the `_raw_log != null` guard) yet carries no catch-all
    (the GOCORTEX_UNMODELLED sentinel). Such a filter drops the unmatched
    records, so a `datamodel` search returns fewer rows than the raw
    dataset. Advisory only (warning severity), so the exit code stays 0.
    See references/record-classification.md."""
    if not _is_model(code_lines):
        return []
    if _CATCHALL_SENTINEL in "\n".join(code_lines):
        return []
    stage_of, start_idx = _classify_stages(code_lines)
    out: List[dict] = []
    seen_starts: set = set()
    for i, kind in enumerate(stage_of):
        if kind != "filter":
            continue
        start = start_idx[i]
        if start in seen_starts:
            continue
        seen_starts.add(start)
        pred_lines = [
            _strip_strings(code_lines[j])
            for j in range(len(stage_of))
            if start_idx[j] == start and stage_of[j] == "filter"
        ]
        pred = " ".join(pred_lines)
        pred = re.sub(r"^\s*\|?\s*filter\b", "", pred, count=1)
        stripped = _NULL_GUARD_RE.sub("", pred)
        remainder = re.sub(r"\b(and|or|not)\b", " ", stripped, flags=re.IGNORECASE)
        remainder = re.sub(r"[()\s\"']", "", remainder)
        if remainder:
            out.append(
                _violation(
                    "WARN-046",
                    "warning",
                    start + 1,
                    "This filter narrows records by content beyond the "
                    "_raw_log != null guard, but the rule has no catch-all, "
                    "so a datamodel search returns fewer rows than the raw "
                    "dataset (the unmatched records are dropped).",
                    "Keep only filter _raw_log != null, classify per record, "
                    "and give unmatched records the catch-all "
                    'xdm.event.original_event_type = "GOCORTEX_UNMODELLED" '
                    "(see references/record-classification.md).",
                )
            )
    return out


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
    findings += _check_warn038(code_lines)
    findings += _check_warn039(code_lines)
    findings += _check_warn040(code_lines)
    findings += _check_warn041(code_lines)
    findings += _check_warn042(code_lines)
    findings += _check_warn043(code_lines)
    findings += _check_warn044(code_lines)
    findings += _check_warn045(code_lines)
    findings += _check_warn046(code_lines)
    findings += _check_warn047(code_lines)
    findings += _check_info013(code_lines)

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
