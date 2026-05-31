---
name: cortex-platform-xdm-author
description: Author Cortex XSIAM Data Model Rules in Cortex Query Language (XQL). Turns a raw vendor log sample into a production-ready rule with a MAPPED-header comment block.
---

# cortex-platform-xdm-author

Author Cortex XSIAM data model rules in Cortex Query Language (XQL) from raw vendor log samples.

The reference files under [references/](references/) document the parser conformance rules, XDM schema, extraction and transformation patterns, and known pitfalls. The scripts validate rules instead of relying on a mental checklist.

## Scope

In scope: Data Model Rules (`[MODEL: dataset=..._raw]`).

Out of scope:

- Parsing rules (`[INGEST: ...]`). The references mention them only in validation rules ERR-001 / 002 / 003 / 005 and in the MAPPED-header instruction.
- Reading parser-stamped underscore anchor columns. A MODEL rule must derive every value from the raw dataset columns (or `_raw_log`), never by coalescing a parser-only `_` anchor. Cortex validates a MODEL rule statically against the dataset schema, where parser-only `_` anchors do not exist, so reading one is rejected as an unknown field before any `coalesce()` fallback can run (see ERR-027). Re-derive from raw instead.

The field-anchor synonym index is in scope as a static lookup table. The bundle ships a CLI to query it.

## Inputs accepted

1. Required: at least one raw log sample (JSONL, plain JSON, syslog text, CEF -- anything Cortex XSIAM ingests as `_raw_log`). If no sample is supplied, ask for one. Do NOT guess vendor field names.
2. Optional: vendor / product / dataset name. Infer from the log and confirm before emitting.

## Outputs produced

One XQL file (or one code block if inline), containing:

- A MAPPED-header comment block (mandatory). Vendor / product / dataset / one-paragraph description / Alert-or-Event Field Mapping with `->` arrows / NOT MAPPED list with reasons / SPDX licence. See [assets/modeling_header_template.xql](assets/modeling_header_template.xql).
- A `[MODEL: dataset=<vendor>_<product>_raw]` block in the three-stage shape: `filter` -> `alter` (extract) -> `alter` (assign).

## Authoring workflow

Full long-form in [references/workflow.md](references/workflow.md). Quick reference:

1. Confirm sample present. If not, ask for one.
2. Profile the sample with `python3 scripts/profile_log.py "<path/to/sample>"`. The script detects the format, walks each record into leaf paths (including `transactions[].http.method` array shapes and `{name, value}` header-pair arrays), infers field types, computes per-field null rates, flags every object-array's discriminator key, and attaches ranked XDM candidates per field. JSON worksheet by default; `--format text` for a table. If the script cannot run, fall back to the manual analysis in [references/workflow.md](references/workflow.md) Step 2.
3. Pick extraction pattern A / B / C / D -- see [references/extraction-patterns.md](references/extraction-patterns.md). The profiler's `detected_format` and `object_arrays.discriminator` outputs map onto the pattern decision tree:
   - `_raw_log` contains JSON string -> A or C
   - `_raw_log` contains syslog / text -> B
   - `_raw_log` is null, fields are pre-parsed top-level columns -> D
   - object-array with a discriminator -> D' projection per discriminator value
4. Look up XDM targets via `python3 scripts/lookup_anchor.py <vendor_field_name>`. Treat frequency `>= 10` as a strong match, `3 - 9` as the default inclusion gate, `1 - 2` as a candidate-only signal, `0` as no XDM home (document in the NOT MAPPED block). If the script is unreachable, grep `assets/field_anchors.json` directly.
5. Cross-reference types against [references/xdm-schema.md](references/xdm-schema.md) and apply the transformation patterns in [references/transformation-patterns.md](references/transformation-patterns.md): numeric coercion, companion pairs, array wrapping, banded scoring, one-sided actor mirroring.
6. Draft the rule. Three stages minimum: `filter` (null guard), `alter` (extract `_temp` variables), `alter` (assign XDM fields). End with semicolon, no trailing comma. Prefix with the MAPPED-header block.
7. Lint. `python3 scripts/lint_rule.py <rule.xql>` covers ERR-012, ERR-013, ERR-014, ERR-015, ERR-016, ERR-017, ERR-018, ERR-024, ERR-027, plus the INFO-012 cascade hint.
8. Fix earliest-first. The earliest violation is almost always the root cause; the rest are cascade noise. See INFO-012 in [references/parser-idioms.md](references/parser-idioms.md).
9. Re-lint until clean, then emit the final output.

## Note on intermediate variables

Underscore-prefixed temporaries (`_<name>`) are conventional in XDM data model rules. The dataset model layer drops these intermediates at query time, so an explicit `| fields -<temp1>, -<temp2>, ...` cleanup stage is NOT idiomatic in a MODEL rule (it belongs to parsing rules, where intermediates use the `tmp_*` prefix and must be dropped explicitly). The bundled `lint_rule.py` therefore does NOT flag a missing cleanup stage. See [references/extraction-patterns.md](references/extraction-patterns.md) "A note on intermediate variables".

## Output discipline

XQL is a formal language, not a creative-writing surface. Emission discipline matters as much as content correctness:

- Emit the rule, not narration about emitting the rule. No "I'll now draft the rule that...", no "Here is the rule:". The MAPPED header is the documentation; the rule body is the answer.
- Determinism over variety. Two runs against the same log sample should produce the same rule. Pick the highest-frequency XDM target from the field-anchor index (workflow step 4) rather than rotating through alternatives.
- One draft, then lint, then fix-earliest-first. Do not draft three variants and pick one. Draft once, run `scripts/lint_rule.py`, fix the earliest violation, re-lint. See workflow steps 6-9.
- No re-verification loops. Trust the linter. If it reports nothing, the rule is done. If it reports something, fix that one thing.
- No "Not available" enumeration. A vendor field with no XDM home goes in the NOT MAPPED block with a one-line reason. It does NOT generate a list of XDM fields considered and rejected.
- Stop when done. No "let me also check...", no postscript on future improvements. The rule plus its MAPPED header is the deliverable.

These rules exist because the Cortex parser is the ground truth. A rule that reads beautifully but the parser rejects is worse than a rule that reads tersely but the parser accepts.

## Hard rules (do not violate)

- Never invent XDM field paths. Every `xdm.*` path must appear in [references/xdm-schema.md](references/xdm-schema.md). If a vendor field has no XDM home, document it in the NOT MAPPED block.
- Never invent `XDM_CONST` values. Closed lists in [references/xdm-const.md](references/xdm-const.md). If no constant matches, OMIT the field and fall back to the String alternative per [references/pitfall-traps.md](references/pitfall-traps.md).
- Never use infix arithmetic inside `alter`. Use `add()`, `subtract()`, `multiply()`, `divide()` -- see [references/parser-idioms.md](references/parser-idioms.md) (ERR-012).
- Never assign a raw numeric score to `xdm.alert.severity`. Apply banded scoring per [references/transformation-patterns.md](references/transformation-patterns.md).
- Always emit the MAPPED header. Without it the rule is not accepted by the GoCortex pack convention.
- Always use British English in comments (normalise, analyse, behaviour, colour).

## References (load on demand)

- [references/workflow.md](references/workflow.md) -- full step-by-step
- [references/modeling-rules.md](references/modeling-rules.md) -- `[MODEL: ...]` structure
- [references/xql-language.md](references/xql-language.md) -- rule structure, functions, operators
- [references/parser-idioms.md](references/parser-idioms.md) -- ERR-012 through ERR-019, INFO-012 (note: ERR-019 is a dataflow check; `lint_rule.py` does not catch it -- verify by hand)
- [references/xdm-schema.md](references/xdm-schema.md) -- 645-field XDM path list
- [references/xdm-const.md](references/xdm-const.md) -- closed-list constants
- [references/extraction-patterns.md](references/extraction-patterns.md) -- A / B / C / D extraction patterns
- [references/transformation-patterns.md](references/transformation-patterns.md) -- coercion, companion pairs, banded scoring, mirroring
- [references/pitfall-traps.md](references/pitfall-traps.md) -- non-existent paths, confused pairs
- [references/compatibility-notes.md](references/compatibility-notes.md) -- `_gc_raw` caveats, deprecated fields
- [references/failure-modes.md](references/failure-modes.md) -- "if you see this in your draft, stop and do that" empirical notes
- [references/worked-examples.md](references/worked-examples.md) -- index of five end-to-end log-to-rule walkthroughs; each lives in its own file under [references/worked-examples/](references/worked-examples/) so you load only the pattern in front of you

## Scripts

All three scripts are Python 3.9+ stdlib only -- no Node, no `pip install`, no network access. Run from the bundle root:

- `python3 scripts/profile_log.py <sample>` -- static profiler for a raw vendor log sample. Detects format (JSON, JSONL, CEF, LEEF, syslog, key=value, CSV, TSV), walks each record into leaf paths (with `[]` markers and per-name entries for `{name, value}` header-pair arrays), infers types, computes per-field null rates, flags object-array discriminators, attaches ranked XDM candidates. JSON worksheet by default; `--format text` for a table. Exits 0 on success, 1 on argument error, 2 on unreadable or unparseable input.
- `python3 scripts/lookup_anchor.py <vendor_field_name>` -- ranked XDM target candidates from the field-anchor index. The index ships under `assets/field_anchors.json`.
- `python3 scripts/lint_rule.py <rule.xql>` -- standalone syntactic linter. Covers ERR-012, ERR-013, ERR-014, ERR-015, ERR-016, ERR-017, ERR-018, ERR-024, ERR-027, INFO-012. Exits 0 on clean, 1 if any error-severity violation fires. ERR-019 (every `_temp` reaches an `xdm.*` assignment), ERR-025, INFO-006, and WARN-020 / WARN-030 / WARN-035 require dataflow or XDM-schema analysis and are out of scope for this linter -- check by hand or via the upstream IDE engine.

If the scripts cannot run (no Python available), treat the markdown references as the authoritative checklist: walk [references/parser-idioms.md](references/parser-idioms.md) (ERR-012 through ERR-019, plus idioms (xi) / (xii); ERR-019 is the dataflow check the linter does not perform, so trace every `_temp` to an `xdm.*` consumer by eye), [references/modeling-rules.md](references/modeling-rules.md) (validation checklist), and [references/pitfall-traps.md](references/pitfall-traps.md) before emitting the rule.

## Bundle integrity tests

The bundle ships Python stdlib tests under [tests/](tests/). They cover JSON validity, SPDX-header presence, frontmatter shape, doc-to-schema consistency for every `xdm.*` and `XDM_CONST.*` cited in the references, ASCII-only and no-emphasis hygiene, the MAPPED-header template's required rows, and the linter's behaviour on a set of fixtures. Run from the bundle root:

```sh
python3 -m unittest discover -v -s tests
```

Python 3.9+ stdlib only. These tests cover the bundle itself. The path for linting user XQL rules is `python3 scripts/lint_rule.py`. See [tests/README.md](tests/README.md) for what each test guards.
