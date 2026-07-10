---
name: cortex-platform-xdm-author
description: Author Cortex XSIAM Data Model Rules in Cortex Query Language (XQL). Turns a raw vendor log sample into a production-ready rule with a MAPPED-header comment block.
version: 1.7.0
---

# cortex-platform-xdm-author

Author Cortex XSIAM data model rules in Cortex Query Language (XQL) from raw vendor log samples.

Version 1.7.0 makes classification a PER-RECORD decision. Every rule decides `xdm.event.type` and `xdm.event.tags` on each record from its own discriminators (not one label stamped across the feed), draws tags from the full closed six-member `EVENT_TAG` enum (authentication, network, cloud, saas, onprem, vpn), and gives any record it cannot classify a catch-all (`xdm.event.original_event_type = "GOCORTEX_UNMODELLED"`, blank tags) so a `datamodel` search never returns fewer rows than the raw dataset. (Version 1.6.1 added a process / command-execution mapping capability and a verified extraction-recipe layer, corrected `xdm.auth.service` to the authentication service name, and broadened vendor field-name coverage.) On top of base rule authoring, the skill provides these auto-detected mapping capabilities, each backed by an advisory linter check:

- Record-level classification and catch-all (new in 1.7.0) -- `xdm.event.type` and `xdm.event.tags` are decided per record via `if()`, tags come from the closed six-member `EVENT_TAG` enum, an unrecognised record falls through to blank tags, and nothing is filtered out (unclassified records get the `GOCORTEX_UNMODELLED` sentinel so the datamodel row count equals the raw count). WARN-045 flags an invented tag; WARN-046 flags a content filter that drops records without a catch-all. See [references/record-classification.md](references/record-classification.md).
- Syslog Stage 0 envelope -- PRI-anchored host capture and priority decode for any syslog source (WARN-040 / WARN-041).
- Authentication Story -- the mandatory XDM field set for login / logon / MFA / SSO events, including the account-class fields `identity_type` / `user_type` and `xdm.auth.service` as the service name (Kerberos, NTLM, OAuth2, SSO, ...), with type-valid fail-safe padding (WARN-042).
- Network / Firewall Story -- the mandatory XDM field set for firewall, flow, proxy, IDS/IPS and DNS traffic events (WARN-043). Network is the foundational layer, so an IDS or WAF event maps it on top of its primary role, and a dual event (a VPN login) takes both story sets.
- Process / command execution (new in 1.6.1) -- the recommended `xdm.*.process.*` set for endpoint / EDR process starts, command executions and script runs (WARN-044), including AAA / network-device command accounting (a TACACS+ `cmd=` record), which is a command execution mapped to `xdm.target.process.command_line` with operation `OPERATION_TYPE_AUDIT` -- not authentication.
- AAA gateways -- TACACS+ / RADIUS / Cisco ISE syslog, with the correct source/target topology, UPN-shaped identities, and command-accounting routed to the process family.

Extraction is aided by [references/extraction-recipes.md](references/extraction-recipes.md) -- verified regex starting points for the common syslog / text / CEF / LEEF shapes -- and by a broad field-anchor index that resolves raw vendor field names to their XDM location. The reference files under [references/](references/) document the parser conformance rules, XDM schema, extraction and transformation patterns, the mapping sets, and known pitfalls. The scripts validate rules instead of relying on a mental checklist.

## Scope

In scope: Data Model Rules (`[MODEL: dataset=..._raw]`).

Out of scope:

- Parsing rules (`[INGEST: ...]`). The references mention them only in validation rules ERR-001 / 002 / 003 / 005 and in the MAPPED-header instruction.
- Reading parser-stamped underscore anchor columns. A MODEL rule must derive every value from the raw dataset columns (or `_raw_log`), never by coalescing a parser-only `_` anchor. Cortex validates a MODEL rule statically against the dataset schema, where parser-only `_` anchors do not exist, so reading one is rejected as an unknown field before any `coalesce()` fallback can run (see ERR-027). Re-derive from raw instead.

The field-anchor synonym index is in scope as a static lookup table. The bundle ships a CLI to query it.

## Inputs accepted

1. Required: at least one raw log sample (JSONL, plain JSON, syslog text, CEF -- anything Cortex XSIAM ingests as `_raw_log`). If no sample is supplied, ask for one. Do NOT guess vendor field names.
2. Optional: vendor / product / dataset name. These cannot be derived from the log body; infer them from the product or API title, then flag them as tenant-adjustable in the MAPPED header, naming the three touch-points the reviewer edits: `xdm.observer.vendor`, `xdm.observer.product`, and the `[MODEL: dataset=...]` header.

## Outputs produced

One XQL file (or one code block if inline), containing:

- A MAPPED-header comment block (mandatory). Vendor / product / dataset / one-paragraph description / Alert-or-Event Field Mapping with `->` arrows / NOT MAPPED list with reasons / SPDX licence. See [assets/modeling_header_template.xql](assets/modeling_header_template.xql).
- A provenance block (mandatory), emitted verbatim as comment lines near the top so a script can grep it. Fill `GOCORTEX_SKILLS_MODEL` with the model id that authored the rule, `GOCORTEX_SKILLS_SKILL_NAME` / `GOCORTEX_SKILLS_SKILL_VERSION` from this skill's frontmatter (`cortex-platform-xdm-author` / `1.7.0`), and `GOCORTEX_SKILLS_SKILL_WARNING_COUNT` with the advisory count from the final `scripts/lint_rule.py` run:
  ```
  // Generated via
  // GOCORTEX_SKILLS_MODEL="<model id>"
  // GOCORTEX_SKILLS_SKILL_NAME="cortex-platform-xdm-author"
  // GOCORTEX_SKILLS_SKILL_VERSION="1.7.0"
  // GOCORTEX_SKILLS_SKILL_WARNING_COUNT="<lint warning count>"
  ```
  `scripts/scaffold_rule.py` emits this automatically (name / version from SKILL.md, model and count from the build environment or its self-lint); when hand-authoring, add it yourself.
- The commented REVIEW UNMODELLED query (mandatory) so unclassified records are discoverable -- see [references/record-classification.md](references/record-classification.md).
- A `[MODEL: dataset=<vendor>_<product>_raw]` block in the three-stage shape: `filter` -> `alter` (extract) -> `alter` (assign).

## Authoring workflow

Full long-form in [references/workflow.md](references/workflow.md). Quick reference:

1. Confirm sample present. If not, ask for one.
2. Profile the sample with `python3 scripts/profile_log.py "<path/to/sample>"`. The script detects the format, walks each record into leaf paths (including `transactions[].http.method` array shapes and `{name, value}` header-pair arrays), infers field types, computes per-field null rates, flags every object-array's discriminator key, attaches ranked XDM candidates per field, and emits a `recommended_pattern` block. JSON worksheet by default; `--format text` for a table. If the script cannot run, fall back to the manual analysis in [references/workflow.md](references/workflow.md) Step 2.
3. Pick the extraction pattern. The profiler's `recommended_pattern` already maps `detected_format` and the object-array discriminators onto the decision tree below; confirm it against [references/extraction-patterns.md](references/extraction-patterns.md):
   - `_raw_log` contains JSON string -> A or C
   - `_raw_log` contains syslog / text -> B (if it opens with a `<NNN>` priority token, parse the Stage 0 envelope first -- see [references/syslog-envelope.md](references/syslog-envelope.md) -- then apply B to the payload)
   - `_raw_log` is null, fields are pre-parsed top-level columns -> D
   - object-array with a discriminator -> D' projection per discriminator value
4. Look up XDM targets via `python3 scripts/lookup_anchor.py <vendor_field_name>`. Treat frequency `>= 10` as a strong match, `3 - 9` as the default inclusion gate, `1 - 2` as a candidate-only signal. A `0` result means no anchor PRECEDENT -- the index records what past rules mapped, it is NOT the schema. Do NOT conclude the field has no XDM home from a `0`: first grep [references/xdm-schema.md](references/xdm-schema.md) for the concept (`auth`, `mfa`, `host`, `process`, ...). Only document a field in NOT MAPPED when xdm-schema.md genuinely has no field for it. Example: `mfa_method` returns `0` anchors but `xdm.auth.mfa.method` exists. If the script is unreachable, grep `assets/field_anchors.json` directly.
5. Cross-reference types against [references/xdm-schema.md](references/xdm-schema.md) and apply the transformation patterns in [references/transformation-patterns.md](references/transformation-patterns.md): numeric coercion, companion pairs, array wrapping, banded scoring, one-sided actor mirroring, authentication / MFA mapping (`xdm.auth.mfa.method`, `xdm.auth.is_mfa_needed`, plus the `xdm.event.operation` classification via `XDM_CONST.OPERATION_TYPE_*`). When the profiler flags an authentication event, apply the full mandatory XDM field set in [references/authentication-mapping.md](references/authentication-mapping.md) (the linter raises the advisory WARN-042 for each mandatory field left unmapped). When it flags a network event, apply the mandatory set in [references/network-mapping.md](references/network-mapping.md) likewise (advisory WARN-043). The two are independent, and network is the foundational layer: IDS, WAF, proxy and similar profiles describe a network flow on top of their primary role, and an authentication event carrying the full transport tuple is also a network connection. A dual event takes BOTH sets, with the union of the story tags in ONE `xdm.event.tags = arraycreate(...)`. When it flags a process / command-execution event, apply the recommended `xdm.*.process.*` mapping in [references/process-mapping.md](references/process-mapping.md) (advisory WARN-044). This is a recommended set, not a mandatory story. AAA / network-device command accounting (a `cmd=` record) is a command execution, not authentication: map its command to `xdm.target.process.command_line` with `xdm.event.type` a process value, operation `OPERATION_TYPE_AUDIT` and no outcome, and do NOT tag it `EVENT_TAG_AUTHENTICATION` (only the AUTHEN login and AUTHOR authorization shapes are authentication). Classification is PER RECORD throughout: decide `xdm.event.type` and `xdm.event.tags` on each record via one `if()` over the closed six-member `EVENT_TAG` enum (ending with no default, so an unrecognised record gets blank tags), filter only `_raw_log != null`, and give any record you cannot classify the catch-all (`xdm.event.original_event_type = "GOCORTEX_UNMODELLED"`) plus the commented REVIEW UNMODELLED query, so a `datamodel` search returns the same row count as the raw dataset (see [references/record-classification.md](references/record-classification.md); WARN-045 flags an invented tag, WARN-046 a record-dropping filter).
6. Draft the rule. Three stages minimum: `filter` (null guard), `alter` (extract `_temp` variables), `alter` (assign XDM fields). End with semicolon, no trailing comma. Prefix with the MAPPED-header block. By default, also emit a deterministic `xdm.event.description` summary built with `concat()` over the identifying fields (vendor action, subject, outcome, and so on) -- see [references/transformation-patterns.md](references/transformation-patterns.md) structured event description. This is an ADDITION to the structured XDM fields, never a substitute: map each value to its own field first, then summarise. Do not bury data in the description that belongs in a queryable field.
7. Lint. `python3 scripts/lint_rule.py <rule.xql>` runs the structural, schema-aware, and dataflow checks: ERR-009/010/011/012/013/014/015/016/017/018/019/020/024/025/027, WARN-014/015/017/018/035/037/038/039/040/041/042/043/044, plus the INFO-012 cascade hint and the INFO-013 over-mapping advisory. It reads the XDM schema and XDM_CONST lists from the references and runs a reach + array-typing pass, so the schema and dataflow checks happen offline.
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
- No "Not available" enumeration. A vendor field with no XDM home (confirmed against [references/xdm-schema.md](references/xdm-schema.md), not just a zero anchor result) goes in the NOT MAPPED block with a one-line reason. It does NOT generate a list of XDM fields considered and rejected.
- Stop when done. No "let me also check...", no postscript on future improvements. The rule plus its MAPPED header is the deliverable.

These rules exist because the Cortex parser is the ground truth. A rule that reads beautifully but the parser rejects is worse than a rule that reads tersely but the parser accepts.

## Hard rules (do not violate)

- Never invent XDM field paths. Every `xdm.*` path must appear in [references/xdm-schema.md](references/xdm-schema.md). If a vendor field has no XDM home, document it in the NOT MAPPED block -- but only after confirming the schema genuinely lacks a field for the concept. A zero anchor-index result is not that confirmation (the index is a precedent table, not the schema).
- Never invent `XDM_CONST` values. Closed lists in [references/xdm-const.md](references/xdm-const.md). If no constant matches, OMIT the field and fall back to the String alternative per [references/pitfall-traps.md](references/pitfall-traps.md).
- Never use infix arithmetic inside `alter`. Use `add()`, `subtract()`, `multiply()`, `divide()` -- see [references/parser-idioms.md](references/parser-idioms.md) (ERR-012).
- Never assign a raw numeric score to `xdm.alert.severity`. Apply banded scoring per [references/transformation-patterns.md](references/transformation-patterns.md).
- Never echo a log-level word into `xdm.alert.severity`. Words like `warning`, `error`, `notice`, `debug` are syslog levels, not severity bands. Band them to Informational / Low / Medium / High / Critical and map the raw level to `xdm.event.log_level` -- see [references/transformation-patterns.md](references/transformation-patterns.md) log-level vocabulary (WARN-037).
- Always end a categorical if-chain into a free-String XDM field that carries vendor text (`xdm.alert.subcategory`, `xdm.observer.action`, `xdm.alert.original_threat_name`, and similar) with a `_field != null, _field` passthrough, so an unmapped vendor value is preserved rather than silently nulled. This does NOT apply to closed-list `XDM_CONST` targets (omit the default -> null) nor to band-vocabulary fields like `xdm.alert.severity` (floor to a band, never echo raw).
- Always emit the MAPPED header. It is the required prefix for every rule -- see [references/modeling-rules.md](references/modeling-rules.md) and [assets/modeling_header_template.xql](assets/modeling_header_template.xql).
- Always use British English in comments (normalise, analyse, behaviour, colour).

## Mapping decision checklist

Run this before emitting, so the same log maps the same way every time. Each item is a deterministic rule, not a judgement call:

- Outcome only on a real result. Set `xdm.event.outcome` only when the log reports success / failure / blocked. A detection disposition (`alert`, `monitor`, `isolate`) is NOT an outcome -- keep it in `xdm.observer.action` (see transformation-patterns.md "Event outcome").
- Host + IP -> emit the address companion. When `xdm.<side>.host.hostname` and `xdm.<side>.ipv4` are both set, also set `xdm.<side>.host.ipv4_addresses = if(ip != null, arraycreate(ip), null)` (WARN-038).
- Syslog source -> parse the envelope (Stage 0) before the payload. Anchor the host on the `<NNN>` priority token (never a vendor literal), and decode the priority into `xdm.event.log_level` / `xdm.alert.severity` as a fallback under the payload severity -- see [references/syslog-envelope.md](references/syslog-envelope.md) (WARN-040 vendor-anchored header, WARN-041 priority captured but never decoded).
- Named asset is a host, cloud object is a resource. An OT / ICS asset (`asset=PLC-17`) or server name goes to `xdm.target.host.hostname`; a cloud resource goes to `xdm.target.resource.name` (see pitfall-traps.md).
- Numeric severity scale -> band both fields. Read the vendor band table, normalise labels to Critical / High / Medium / Low (vendor `Moderate` -> `Medium`), and emit both `xdm.alert.severity` and `xdm.event.log_level` (transformation-patterns.md "Banded numeric scoring").
- Risk / deviation metric -> `xdm.alert.risks`. A ratio or deviation with no typed numeric home is parked in `xdm.alert.risks` (String), not dropped. If you do drop it, write "intentionally omitted", never "no XDM home".
- Vendor / product / dataset are tenant-adjustable. Infer them, and flag the three touch-points (`xdm.observer.vendor`, `xdm.observer.product`, `[MODEL: dataset=...]`) in the MAPPED header.
- Never bury a value that has a structured home. The description summarises with `concat()` over the fields that matter; it never substitutes for a queryable field, and it NEVER receives the whole payload (`_raw_log` or `to_json_string(...)` -- WARN-039). See also WARN-038 / INFO-013 and failure-modes.md.

## References (load on demand)

- [references/workflow.md](references/workflow.md) -- full step-by-step
- [references/modeling-rules.md](references/modeling-rules.md) -- `[MODEL: ...]` structure
- [references/xql-language.md](references/xql-language.md) -- rule structure, functions, operators
- [references/parser-idioms.md](references/parser-idioms.md) -- ERR-012 through ERR-019, INFO-012
- [references/xdm-schema.md](references/xdm-schema.md) -- 645-field XDM path list
- [references/xdm-const.md](references/xdm-const.md) -- closed-list constants
- [references/extraction-patterns.md](references/extraction-patterns.md) -- A / B / C / D extraction patterns
- [references/extraction-recipes.md](references/extraction-recipes.md) -- verified regex recipes for common syslog / text / CEF / LEEF shapes (advisory starting points for Pattern B; each proven lint-clean and by the verifier)
- [references/syslog-envelope.md](references/syslog-envelope.md) -- Stage 0 transport layer for syslog sources (PRI-anchored host + priority decode)
- [references/transformation-patterns.md](references/transformation-patterns.md) -- coercion, companion pairs, banded scoring, mirroring
- [references/authentication-mapping.md](references/authentication-mapping.md) -- mandatory XDM field set for authentication events (auto-detected; advisory WARN-042)
- [references/network-mapping.md](references/network-mapping.md) -- mandatory XDM field set for network events (auto-detected; advisory WARN-043; dual-story tag union)
- [references/process-mapping.md](references/process-mapping.md) -- recommended XDM mapping for process / command-execution events (endpoint / EDR process starts, script runs, AAA command accounting; auto-detected, advisory WARN-044)
- [references/record-classification.md](references/record-classification.md) -- per-record classification of `xdm.event.type` / `xdm.event.tags` over the closed six-member EVENT_TAG enum, and the catch-all that keeps the datamodel row count equal to the raw count (advisory WARN-045 / WARN-046)
- [references/pitfall-traps.md](references/pitfall-traps.md) -- non-existent paths, confused pairs
- [references/compatibility-notes.md](references/compatibility-notes.md) -- `_gc_raw` caveats, deprecated fields
- [references/failure-modes.md](references/failure-modes.md) -- "if you see this in your draft, stop and do that" empirical notes
- [references/worked-examples.md](references/worked-examples.md) -- index of eight end-to-end log-to-rule walkthroughs (patterns A-D', the syslog envelope, the authentication and network stories, and AAA); each lives in its own file under [references/worked-examples/](references/worked-examples/) so you load only the pattern in front of you

## Scripts

All scripts are Python 3.9+ stdlib only -- no Node, no `pip install`, no network access. Run from the bundle root. The typical loop is profile -> scaffold -> lint -> verify.

- `python3 scripts/profile_log.py <sample>` -- static profiler for a raw vendor log sample. Detects format (JSON, JSONL, CEF, LEEF, syslog, key=value, CSV, TSV), walks each record into leaf paths (with `[]` markers and per-name entries for `{name, value}` header-pair arrays), infers types, computes per-field null rates, flags object-array discriminators, attaches ranked XDM candidates, and recommends an extraction pattern. JSON worksheet by default; `--format text` for a table. Exits 0 on success, 1 on argument error, 2 on unreadable or unparseable input.
- `python3 scripts/scaffold_rule.py <worksheet.json>` -- turns a profiler worksheet (path or `-` for stdin) into a complete, lint-clean starter MODEL rule: MAPPED header, extraction stage, and an XDM drain wired from the worksheet's anchor candidates. `--vendor` / `--product` / `--dataset` set the identity. Self-gates through the linter before printing.
- `python3 scripts/lookup_anchor.py <vendor_field_name>` -- ranked XDM target candidates from the field-anchor index. `--reverse <xdm.path>` lists the vendor synonyms that fill a target (top-down authoring); `--related <xdm.path>` lists companion / mirror fields. The index ships under `assets/field_anchors.json`.
- `python3 scripts/xdm_const_mapper.py --field <xdm.path> --values a,b,c` -- emits the `if()`-chain mapping vendor values to the field's XDM_CONST members (never invents a constant). `--banded` emits the paired severity / log-level chains for a score column.
- `python3 scripts/mitre_map.py --kind technique --ids T1078,T1059` -- maps MITRE technique / tactic IDs or `--names` to `XDM_CONST.MITRE_*` constants and emits the `arraymap` chain. Validated against the documented MITRE lists; unmapped inputs are reported, not invented.
- `python3 scripts/lint_rule.py <rule.xql>` -- the rule linter. Structural and parser-conformance checks (ERR-009/010/011/012/013/014/015/016/017/018/024/027, WARN-015/017/018, INFO-012), schema-aware checks read from the references (ERR-020 invented path, WARN-014 quoted XDM_CONST, WARN-035 array-vs-scalar shape, WARN-037 log-level word in severity, WARN-038 missing host.ipv4_addresses companion, WARN-039 whole payload dumped into the description, WARN-040 vendor-anchored syslog header, WARN-041 syslog priority captured but never decoded, WARN-042 authentication-story mandatory set advisory, WARN-043 network-story mandatory set advisory, WARN-044 process / command-execution advisory -- the executable-parent misuse, WARN-045 invented EVENT_TAG outside the closed six-member enum, WARN-046 record-dropping content filter with no catch-all sentinel), dataflow checks over the rule's temps (ERR-019 unused temp, ERR-025 concat-hidden temp; both scoped to `_gc_raw` datasets, where they are a hard block), and the INFO-013 over-mapping advisory (one temp across 3+ entity families). Exits 0 on clean, 1 if any error-severity violation fires. INFO-006 (cleanup stage) is intentionally not emitted -- see the note above.
- `python3 scripts/verify_rule.py <rule.xql> <sample.json>` -- evaluates the rule against the sample offline and prints the resulting `xdm.*` map per record, so you can confirm behaviour without a tenant. `--expect <expected.json>` diffs against expected output. Unsupported constructs are reported, not guessed.

If the scripts cannot run (no Python available), treat the markdown references as the authoritative checklist: walk [references/parser-idioms.md](references/parser-idioms.md) (ERR-012 through ERR-019, plus idioms (xi) / (xii)), [references/modeling-rules.md](references/modeling-rules.md) (validation checklist), and [references/pitfall-traps.md](references/pitfall-traps.md) before emitting the rule.

## Bundle integrity tests

The bundle ships Python stdlib tests under [tests/](tests/). They cover JSON validity, SPDX-header presence, frontmatter shape, doc-to-schema consistency for every `xdm.*` and `XDM_CONST.*` cited in the references, ASCII-only and no-emphasis hygiene, the MAPPED-header template's required rows, and the linter's behaviour on a set of fixtures. Run from the bundle root:

```sh
python3 -m unittest discover -v -s tests
```

Python 3.9+ stdlib only. These tests cover the bundle itself. The path for linting user XQL rules is `python3 scripts/lint_rule.py`. See [tests/README.md](tests/README.md) for what each test guards.
