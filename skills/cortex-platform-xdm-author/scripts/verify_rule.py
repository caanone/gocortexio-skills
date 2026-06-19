#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: GoCortexIO
"""verify_rule.py <rule.xql> <sample.(json|jsonl)> [--expect expected.json]

Evaluate a MODEL rule against a raw log sample offline and print the
resulting xdm.* map per record. This replaces the "paste into a tenant
and wait" loop for the majority of edits: it runs the rule's extraction
and mapping logic in pure Python over the supported XQL subset.

Supported: filter / alter stages; the arrow operator (`col -> a.b`,
`col -> field[]`, `col -> []`); json_extract_scalar / json_extract_array;
to_string / to_number / to_integer / to_float / to_boolean; coalesce;
concat; if; lowercase / uppercase / trim / replace; split / arrayindex /
arraycreate / arraystring / arraydistinct / arrayconcat / array_length;
arraymap / arrayfilter (with "@element"); add / subtract / multiply /
divide; parse_epoch; regextract; incidr / incidr6; the comparison and
logical operators (= != ~= >= <= > < contains in and or); and
XDM_CONST.* tokens (evaluated as opaque symbols).

Anything outside that subset is reported as an unsupported construct,
never silently guessed.

Each record's environment binds every top-level key as a column, so both
Pattern A (json_extract_scalar on _raw_log) and Pattern D (arrow on
parsed columns) work. For a JSON object record, `_raw_log` is bound to the
record's JSON text. For a raw-text record (a JSON string in the sample,
for example a syslog line), `_raw_log` is bound to the literal text, so
envelope anchors such as the leading ^<NNN> priority token behave as they
do on a tenant.

Exit codes:
    0   evaluated; with --expect, all records matched
    1   argument error, unsupported construct, or an --expect mismatch
    2   cannot read or parse an input file

Python 3.9+ stdlib only.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class UnsupportedConstruct(Exception):
    pass


# --------------------------------------------------------------------
# Tokeniser
# --------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')
  | (?P<number>\d+\.\d+|\d+)
  | (?P<arrow>->)
  | (?P<op2>!=|>=|<=|~=)
  | (?P<lbracket>\[)
  | (?P<rbracket>\])
  | (?P<punct>[=<>(),.])
  | (?P<ident>@?[A-Za-z_][A-Za-z0-9_]*)
    """,
    re.VERBOSE,
)

_KEYWORDS = {"and", "or", "contains", "in", "null", "true", "false"}


def _tokenise(s: str) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    i = 0
    while i < len(s):
        m = _TOKEN_RE.match(s, i)
        if not m:
            raise UnsupportedConstruct(f"cannot tokenise near: {s[i:i+20]!r}")
        i = m.end()
        kind = m.lastgroup
        if kind == "ws":
            continue
        val = m.group()
        if kind == "ident" and val in _KEYWORDS:
            out.append(("kw", val))
        else:
            out.append((kind, val))
    out.append(("eof", ""))
    return out


# --------------------------------------------------------------------
# Parser -- recursive descent. AST nodes are tuples.
# --------------------------------------------------------------------


class _Parser:
    def __init__(self, tokens: List[Tuple[str, str]]):
        self.toks = tokens
        self.pos = 0

    def _peek(self) -> Tuple[str, str]:
        return self.toks[self.pos]

    def _next(self) -> Tuple[str, str]:
        t = self.toks[self.pos]
        self.pos += 1
        return t

    def _expect(self, kind: str, val: Optional[str] = None) -> Tuple[str, str]:
        t = self._next()
        if t[0] != kind or (val is not None and t[1] != val):
            raise UnsupportedConstruct(f"expected {val or kind}, got {t[1]!r}")
        return t

    def parse(self):
        node = self._or()
        if self._peek()[0] != "eof":
            raise UnsupportedConstruct(f"trailing tokens at {self._peek()[1]!r}")
        return node

    def _or(self):
        node = self._and()
        while self._peek() == ("kw", "or"):
            self._next()
            node = ("or", node, self._and())
        return node

    def _and(self):
        node = self._cmp()
        while self._peek() == ("kw", "and"):
            self._next()
            node = ("and", node, self._cmp())
        return node

    _CMP_OPS = {"=", "!=", ">=", "<=", ">", "<", "~="}

    def _cmp(self):
        node = self._postfix()
        t = self._peek()
        if (t[0] in ("punct", "op2") and t[1] in self._CMP_OPS) or t == ("kw", "contains") or t == ("kw", "in"):
            op = self._next()[1]
            right = self._postfix()
            return ("cmp", op, node, right)
        return node

    def _postfix(self):
        node = self._primary()
        while self._peek() == ("arrow", "->"):
            self._next()
            node = ("arrow", node, self._arrowpath())
        return node

    def _arrowpath(self):
        # path := IDENT ("." IDENT)* ("[]" )?   |   "[]"
        parts: List[str] = []
        if self._peek() == ("lbracket", "["):
            self._next()
            self._expect("rbracket", "]")
            return ("cast_array", [])
        parts.append(self._expect("ident")[1])
        while self._peek() == ("punct", "."):
            self._next()
            parts.append(self._expect("ident")[1])
        is_array = False
        if self._peek() == ("lbracket", "["):
            self._next()
            self._expect("rbracket", "]")
            is_array = True
        return ("path", parts, is_array)

    def _primary(self):
        t = self._peek()
        if t == ("punct", "("):
            self._next()
            node = self._or()
            self._expect("punct", ")")
            return node
        if t[0] == "string":
            self._next()
            return ("str", _unquote(t[1]))
        if t[0] == "number":
            self._next()
            return ("num", float(t[1]) if "." in t[1] else int(t[1]))
        if t == ("kw", "null"):
            self._next()
            return ("null",)
        if t in (("kw", "true"), ("kw", "false")):
            self._next()
            return ("bool", t[1] == "true")
        if t[0] == "ident":
            name = self._next()[1]
            # XDM_CONST.NAME -> opaque symbol
            if name == "XDM_CONST" and self._peek() == ("punct", "."):
                self._next()
                const = self._expect("ident")[1]
                return ("const", f"XDM_CONST.{const}")
            if self._peek() == ("punct", "("):
                return self._call(name)
            return ("ident", name)
        raise UnsupportedConstruct(f"unexpected token {t[1]!r}")

    def _call(self, name: str):
        self._expect("punct", "(")
        args = []
        if self._peek() != ("punct", ")"):
            args.append(self._or())
            while self._peek() == ("punct", ","):
                self._next()
                args.append(self._or())
        self._expect("punct", ")")
        return ("call", name.lower(), args)


def _unquote(tok: str) -> str:
    body = tok[1:-1]
    return body.replace('\\"', '"').replace("\\'", "'").replace("\\\\", "\\")


def parse_expr(text: str):
    return _Parser(_tokenise(text)).parse()


# --------------------------------------------------------------------
# Evaluator
# --------------------------------------------------------------------

_LAZY = {"if", "coalesce", "arraymap", "arrayfilter"}


def _truthy(v: Any) -> bool:
    return v is not None and v is not False


def _to_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v)


def _jsonpath_keys(path: str) -> List[str]:
    p = path.strip()
    if p.startswith("$"):
        p = p[1:]
    keys: List[str] = []
    i = 0
    while i < len(p):
        if p[i] == ".":
            i += 1
            continue
        if p[i] == "[":
            m = re.match(r"\[\s*'([^']*)'\s*\]|\[\s*\"([^\"]*)\"\s*\]", p[i:])
            if not m:
                raise UnsupportedConstruct(f"bad json path segment: {p[i:]!r}")
            keys.append(m.group(1) if m.group(1) is not None else m.group(2))
            i += m.end()
            continue
        m = re.match(r"[^.\[]+", p[i:])
        keys.append(m.group())
        i += m.end()
    return keys


def _walk(obj: Any, keys: List[str]) -> Any:
    cur = obj
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return None
    return cur


def _as_obj(v: Any) -> Any:
    """Coerce a value to a parsed object/array if it is a JSON string."""
    if isinstance(v, str):
        try:
            return json.loads(v)
        except (ValueError, TypeError):
            return v
    return v


class Evaluator:
    def __init__(self, env: Dict[str, Any]):
        self.env = env

    def eval(self, node) -> Any:
        kind = node[0]
        if kind == "str":
            s = node[1]
            if s == "@element" and "@element" in self.env:
                return self.env["@element"]
            return s
        if kind == "num":
            return node[1]
        if kind == "null":
            return None
        if kind == "bool":
            return node[1]
        if kind == "const":
            return node[1]  # opaque XDM_CONST symbol
        if kind == "ident":
            return self.env.get(node[1])
        if kind == "and":
            return _truthy(self.eval(node[1])) and _truthy(self.eval(node[2]))
        if kind == "or":
            return _truthy(self.eval(node[1])) or _truthy(self.eval(node[2]))
        if kind == "cmp":
            return self._cmp(node[1], node[2], node[3])
        if kind == "arrow":
            return self._arrow(node[1], node[2])
        if kind == "call":
            return self._call(node[1], node[2])
        raise UnsupportedConstruct(f"cannot evaluate node {kind}")

    def _cmp(self, op, lnode, rnode) -> Any:
        left = self.eval(lnode)
        right = self.eval(rnode)
        # Equality is an explicit check (handles `x = null` / `x != null`,
        # the idiomatic null guard) and never propagates null.
        if op == "=":
            return _eq(left, right)
        if op == "!=":
            return not _eq(left, right)
        # Ordering propagates null.
        if op in (">=", "<=", ">", "<"):
            ln, rn = _num(left), _num(right)
            if ln is None or rn is None:
                return None
            return {">=": ln >= rn, "<=": ln <= rn, ">": ln > rn, "<": ln < rn}[op]
        if op == "~=":
            if left is None or right is None:
                return None
            return re.search(str(right), str(left)) is not None
        if op == "contains":
            if left is None or right is None:
                return None
            return str(right) in str(left)
        if op == "in":
            if isinstance(right, list):
                return left in right
            return None
        raise UnsupportedConstruct(f"operator {op!r}")

    def _arrow(self, objnode, pathnode) -> Any:
        obj = _as_obj(self.eval(objnode))
        if pathnode[0] == "cast_array":
            if obj is None:
                return None
            return obj if isinstance(obj, list) else [obj]
        _, parts, is_array = pathnode
        val = _walk(obj, parts) if isinstance(obj, (dict, list)) else None
        if is_array:
            if val is None:
                return None
            return val if isinstance(val, list) else [val]
        return val

    def _call(self, name, argnodes) -> Any:
        if name in _LAZY:
            return self._call_lazy(name, argnodes)
        args = [self.eval(a) for a in argnodes]
        fn = _EAGER.get(name)
        if fn is None:
            raise UnsupportedConstruct(f"function {name}()")
        return fn(*args)

    def _call_lazy(self, name, argnodes) -> Any:
        if name == "coalesce":
            for a in argnodes:
                v = self.eval(a)
                if v is not None:
                    return v
            return None
        if name == "if":
            i = 0
            while i + 1 < len(argnodes):
                if _truthy(self.eval(argnodes[i])):
                    return self.eval(argnodes[i + 1])
                i += 2
            if i < len(argnodes):  # trailing default
                return self.eval(argnodes[i])
            return None
        if name in ("arraymap", "arrayfilter"):
            if len(argnodes) != 2:
                raise UnsupportedConstruct(f"{name}() needs 2 args")
            arr = _as_obj(self.eval(argnodes[0]))
            if arr is None:
                return None
            if not isinstance(arr, list):
                raise UnsupportedConstruct(f"{name}() arg is not an array")
            out = []
            for el in arr:
                child = Evaluator({**self.env, "@element": el})
                if name == "arraymap":
                    out.append(child.eval(argnodes[1]))
                else:  # arrayfilter
                    if _truthy(child.eval(argnodes[1])):
                        out.append(el)
            return out
        raise UnsupportedConstruct(f"lazy function {name}()")


def _eq(a: Any, b: Any) -> bool:
    an, bn = _num(a), _num(b)
    if an is not None and bn is not None:
        return an == bn
    return _to_str(a) == _to_str(b)


def _num(v: Any) -> Optional[float]:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v)
        except ValueError:
            return None
    return None


# ----- eager function implementations -----


def _json_extract_scalar(s, path):
    obj = _as_obj(s)
    if not isinstance(obj, (dict, list)):
        return None
    val = _walk(obj, _jsonpath_keys(path))
    if isinstance(val, (dict, list)) or val is None:
        return None
    return _to_str(val)


def _json_extract_array(s, path):
    obj = _as_obj(s)
    if not isinstance(obj, (dict, list)):
        return None
    val = _walk(obj, _jsonpath_keys(path))
    return val if isinstance(val, list) else None


def _to_number(v):
    return _num(v)


def _to_integer(v):
    n = _num(v)
    return None if n is None else int(n)


def _to_boolean(v):
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("true", "1")


def _arrayindex(arr, i):
    if not isinstance(arr, list):
        return None
    try:
        return arr[int(i)]
    except (IndexError, ValueError, TypeError):
        return None


def _arraystring(arr, delim):
    if not isinstance(arr, list):
        return None
    return str(delim).join(_to_str(x) for x in arr if x is not None)


def _split(s, delim):
    if s is None:
        return None
    return str(s).split(str(delim))


def _regextract(s, pattern):
    if s is None:
        return []
    return re.findall(pattern, str(s))


def _incidr(ip, cidr):
    try:
        return ipaddress.ip_address(str(ip)) in ipaddress.ip_network(str(cidr), strict=False)
    except ValueError:
        return None


def _concat(*args):
    return "".join(_to_str(a) or "" for a in args)


_EAGER = {
    "json_extract_scalar": _json_extract_scalar,
    "json_extract_array": _json_extract_array,
    "to_string": _to_str,
    "to_number": _to_number,
    "to_integer": _to_integer,
    "to_float": lambda v: _num(v),
    "to_boolean": _to_boolean,
    "concat": _concat,
    "lowercase": lambda s: None if s is None else str(s).lower(),
    "uppercase": lambda s: None if s is None else str(s).upper(),
    "trim": lambda s: None if s is None else str(s).strip(),
    "replace": lambda s, a, b: None if s is None else str(s).replace(str(a), str(b)),
    "split": _split,
    "arrayindex": _arrayindex,
    "arraycreate": lambda *a: list(a),
    "arraystring": _arraystring,
    "arraydistinct": lambda arr: list(dict.fromkeys(arr)) if isinstance(arr, list) else None,
    "arrayconcat": lambda a, b: (a or []) + (b or []) if (isinstance(a, list) or isinstance(b, list)) else None,
    "array_length": lambda arr: len(arr) if isinstance(arr, list) else None,
    "add": lambda a, b: None if _num(a) is None or _num(b) is None else _num(a) + _num(b),
    "subtract": lambda a, b: None if _num(a) is None or _num(b) is None else _num(a) - _num(b),
    "multiply": lambda a, b: None if _num(a) is None or _num(b) is None else _num(a) * _num(b),
    "divide": lambda a, b: None if not _num(a) or not _num(b) else _num(a) / _num(b),
    "parse_epoch": lambda s, *rest: _to_integer(s),
    "regextract": _regextract,
    "incidr": _incidr,
    "incidr6": _incidr,
}


# --------------------------------------------------------------------
# Rule executor
# --------------------------------------------------------------------


def _strip_comment(line: str) -> str:
    in_dq = in_sq = False
    for i in range(len(line) - 1):
        ch = line[i]
        if ch == '"' and not in_sq:
            in_dq = not in_dq
        elif ch == "'" and not in_dq:
            in_sq = not in_sq
        elif ch == "/" and line[i + 1] == "/" and not in_dq and not in_sq:
            return line[:i]
    return line


def _split_assignments(body: str) -> List[str]:
    """Split an alter body into top-level comma-separated items."""
    out: List[str] = []
    depth = 0
    start = 0
    in_str = None
    for i, ch in enumerate(body):
        if in_str:
            if ch == in_str and body[i - 1] != "\\":
                in_str = None
            continue
        if ch in ('"', "'"):
            in_str = ch
        elif ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(body[start:i])
            start = i + 1
    out.append(body[start:])
    return [a.strip() for a in out if a.strip()]


def _parse_stages(rule_text: str) -> List[Tuple[str, str]]:
    """Return [(stage_kind, body)] for filter / alter stages."""
    lines = [_strip_comment(ln) for ln in rule_text.splitlines()]
    # Drop the MODEL header and a trailing lone semicolon.
    joined: List[str] = []
    for ln in lines:
        if re.match(r"\s*\[MODEL:", ln):
            continue
        joined.append(ln)
    text = "\n".join(joined)
    # Tokenise into stages by the stage keywords at statement start.
    stages: List[Tuple[str, str]] = []
    cur_kind: Optional[str] = None
    cur_body: List[str] = []
    stage_re = re.compile(r"^\s*\|?\s*(filter|alter)\b(.*)$")
    for ln in text.splitlines():
        m = stage_re.match(ln)
        if m and _at_depth_zero(stages, cur_body):
            if cur_kind is not None:
                stages.append((cur_kind, "\n".join(cur_body)))
            cur_kind = m.group(1)
            cur_body = [m.group(2)]
        else:
            if cur_kind is not None:
                cur_body.append(ln)
    if cur_kind is not None:
        stages.append((cur_kind, "\n".join(cur_body)))
    # Strip a trailing ';' from the last stage body.
    if stages:
        k, b = stages[-1]
        stages[-1] = (k, b.rstrip().rstrip(";"))
    return stages


def _at_depth_zero(stages, cur_body) -> bool:
    """A stage keyword only starts a new stage when not inside an open
    paren of the current body."""
    text = "\n".join(cur_body)
    depth = 0
    in_str = None
    for i, ch in enumerate(text):
        if in_str:
            if ch == in_str and text[i - 1] != "\\":
                in_str = None
            continue
        if ch in ('"', "'"):
            in_str = ch
        elif ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
    return depth == 0


def evaluate_rule(rule_text: str, record: Any) -> Optional[Dict[str, Any]]:
    """Run the rule over one record. Returns the xdm.* map, or None if a
    filter dropped the record."""
    env: Dict[str, Any] = {}
    if isinstance(record, dict):
        # A structured (JSON) source: bind every top-level key as a column
        # and present _raw_log as the record's JSON text, the way Cortex
        # does for a JSON-bodied dataset.
        for k, v in record.items():
            env[k] = v
        env["_raw_log"] = json.dumps(record)
    elif isinstance(record, str):
        # A raw-text source (for example a syslog line): _raw_log is the
        # literal text, byte for byte, so regextract anchors such as
        # ^<\d{1,3}> behave exactly as they do on a tenant. Feed these as a
        # JSONL sample where each line is a JSON string.
        env["_raw_log"] = record
    else:
        env["_raw_log"] = json.dumps(record)
    xdm: Dict[str, Any] = {}

    for kind, body in _parse_stages(rule_text):
        if kind == "filter":
            pred = body.strip()
            if not pred:
                continue
            if not _truthy(Evaluator(env).eval(parse_expr(pred))):
                return None
            continue
        # alter: evaluate all RHS against the pre-stage env (parallel
        # semantics), then commit.
        updates: List[Tuple[str, Any]] = []
        for item in _split_assignments(body):
            mm = re.match(r"\s*(xdm\.[\w.]+|_[A-Za-z]\w*|[A-Za-z]\w*)\s*=(?!=)(.*)$", item, re.DOTALL)
            if not mm:
                raise UnsupportedConstruct(f"cannot parse assignment: {item.strip()[:60]!r}")
            lhs = mm.group(1)
            rhs = mm.group(2).strip()
            value = Evaluator(env).eval(parse_expr(rhs))
            updates.append((lhs, value))
        for lhs, value in updates:
            if lhs.startswith("xdm."):
                xdm[lhs] = value
            else:
                env[lhs] = value
    return xdm


def _load_records(text: str) -> List[Any]:
    text = text.strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        records = []
        for ln in text.splitlines():
            ln = ln.strip()
            if ln:
                records.append(json.loads(ln))
        return records


def _normalise(v: Any) -> Any:
    """Compare-friendly form: stringify scalars, recurse arrays."""
    if isinstance(v, list):
        return [_normalise(x) for x in v]
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, (int, float)):
        return _to_str(v)
    return v


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Evaluate a MODEL rule against a sample offline."
    )
    ap.add_argument("rule", help="path to the .xql rule")
    ap.add_argument("sample", help="path to a JSON or JSONL sample")
    ap.add_argument(
        "--expect",
        default=None,
        help="path to expected xdm.* maps (JSON array) to diff against",
    )
    ap.add_argument("--format", choices=("json", "text"), default="json")
    args = ap.parse_args(argv[1:])

    try:
        rule_text = Path(args.rule).read_text(encoding="utf-8")
        sample_text = Path(args.sample).read_text(encoding="utf-8")
    except OSError as exc:
        sys.stderr.write(f"error: cannot read input: {exc}\n")
        return 2

    try:
        records = _load_records(sample_text)
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"error: sample is not valid JSON / JSONL: {exc}\n")
        return 2

    try:
        results = [evaluate_rule(rule_text, rec) for rec in records]
    except UnsupportedConstruct as exc:
        sys.stderr.write(f"error: unsupported construct: {exc}\n")
        return 1

    if args.format == "json":
        sys.stdout.write(json.dumps(results, indent=2, default=str) + "\n")
    else:
        for i, res in enumerate(results):
            sys.stdout.write(f"--- record {i} ---\n")
            if res is None:
                sys.stdout.write("(dropped by filter)\n")
                continue
            for k in sorted(res):
                sys.stdout.write(f"{k} = {res[k]!r}\n")

    if args.expect:
        try:
            expected = json.loads(Path(args.expect).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            sys.stderr.write(f"error: cannot read --expect file: {exc}\n")
            return 2
        mismatches = []
        for i, (got, want) in enumerate(zip(results, expected)):
            got_n = {k: _normalise(v) for k, v in (got or {}).items()}
            want_n = {k: _normalise(v) for k, v in (want or {}).items()}
            for key, wv in want_n.items():
                if got_n.get(key) != wv:
                    mismatches.append((i, key, got_n.get(key), wv))
        if mismatches:
            sys.stderr.write(f"{len(mismatches)} mismatch(es) vs --expect:\n")
            for i, key, gv, wv in mismatches:
                sys.stderr.write(f"  record {i} {key}: got {gv!r}, expected {wv!r}\n")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
