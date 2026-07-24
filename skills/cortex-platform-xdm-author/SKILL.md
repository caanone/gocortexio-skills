---
name: cortex-platform-xdm-author
description: Author Cortex XSIAM Data Model Rules in Cortex Query Language (XQL). Turns a raw vendor log sample into a production-ready rule with a MAPPED-header comment block.
version: 1.8.1
license: AGPL-3.0-or-later
---

# cortex-platform-xdm-author

Author Cortex XSIAM data model rules in Cortex Query Language (XQL) from raw vendor log samples.

The current version is 1.8.1; the per-version change history lives in [CHANGELOG.md](CHANGELOG.md). On top of base rule authoring, the skill provides these auto-detected mapping capabilities, each backed by an advisory linter check:

- Record-level classification and catch-all (new in 1.7.0) -- `xdm.event.type` and `xdm.event.tags` are decided per record via `if()`, tags come from the closed six-member `EVENT_TAG` enum, an unrecognised record falls through to blank tags, and nothing is filtered out (unclassified records get the `GOCORTEX_UNMODELLED` sentinel so the datamodel row count equals the raw count). WARN-045 flags an invented tag; WARN-046 flags a content filter that drops records without a catch-all. See [references/record-classification.md](references/record-classification.md).
- Syslog Stage 0 envelope -- relay-aware host capture and priority decode for any syslog source (WARN-040 / WARN-041). HARD RULE: syslog reaches Cortex both direct and behind an intermediate relay that prepends its own `<PRI>` header, so every generated syslog rule must capture identically for both -- the envelope skips any relay prefix with a greedy `^.*` (origin host + origin PRI) and every payload field is anchored on its own token, never on `^`. A `^`-anchored / positional body capture is flagged WARN-047. See [references/syslog-envelope.md](references/syslog-envelope.md).
- Authentication Story -- the mandatory XDM field set for login / logon / MFA / SSO events, including the account-class fields `identity_type` / `user_type` and `xdm.auth.service` as the service name (Kerberos, NTLM, OAuth2, SSO, ...), with type-valid fail-safe padding (WARN-042). Windows logon (4624 / 4625) and Kerberos (4768 / 4769) are covered: the complete `LOGON_TYPE` list maps the `LogonType` integer, and the full Kerberos encryption-type / error-code enums ship as [assets/kerberos_crosswalk.json](assets/kerberos_crosswalk.json) (rendered by `scripts/kerberos_map.py`) -- see [references/authentication-mapping.md](references/authentication-mapping.md).
- Network / Firewall Story -- the mandatory XDM field set for firewall, flow, proxy, IDS/IPS and DNS traffic events (WARN-043). Network is the foundational layer, so an IDS or WAF event maps it on top of its primary role, and a dual event (a VPN login) takes both story sets.
- Endpoint telemetry -- process / file / registry / image events (Linux commands, Windows Security, Sysmon, EDR) on the channel/verb model: `xdm.event.type` = the channel/source, `xdm.event.original_event_type` = the per-event name, `xdm.event.operation` = the precise verb from the complete 56-member `OPERATION_TYPE` enum. Endpoint events carry blank `xdm.event.tags` (no process story tag). WARN-050 flags a process/file/registry event with no operation verb. See [references/process-mapping.md](references/process-mapping.md).
- Cloud audit story (AWS CloudTrail, Azure Activity / Entra sign-in, GCP Cloud Audit) -- the operation verb is DERIVED from the provider's action-naming convention (CloudTrail `eventName`, Azure `operationName`, GCP `methodName`), the outcome from `errorCode` / `resultType` / `status.code`, and the event is tagged CLOUD (plus AUTHENTICATION for a console login / sign-in). `xdm.*.cloud.provider` is mapped reliably; `xdm.*.cloud.service` (`CLOUD_SERVICE_TYPE`) is set only on a confident match, otherwise the raw service name is kept in `xdm.event.type` / `xdm.event.description` or the NOT MAPPED block -- never `xdm.*.cloud.source_type`, which is a banned internal-only XCloud asset field (lint ERR-029). A permanent accuracy corpus (`scripts/score_mappings.py`) pins the mapping field-for-field against author-curated ground truth. See [references/cloud-mapping.md](references/cloud-mapping.md).
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
3. Optional but recommended: a source reference document that describes the fields -- an OpenAPI / JSON Schema spec or API field docs for a JSON / JSONL source, a message / mnemonic reference for a syslog source, a CEF / LEEF extension dictionary, or a column dictionary for CSV / TSV. A sample alone shows the shape but not the meaning: the reference resolves cryptic field names, authoritative datatypes (array vs scalar -- the class of the `xdm.alert.risks` "expected array" defect), enum values (for `XDM_CONST` mapping) and which fields carry the identity / auth story. The skill ASKS for the format-matched reference after profiling (workflow step 3) and proceeds without it when unavailable, recording the basis in provenance (`GOCORTEX_SKILLS_SOURCE_BASIS`). Accept a link (fetch and mine it), pasted text, or a file path.

## Outputs produced

One XQL file (or one code block if inline). The top comment block MUST follow this fixed order for predictability -- SPDX licence always first, the skill-issues pointer always last:

1. SPDX licence header (`SPDX-FileCopyrightText` + `SPDX-License-Identifier`) -- ALWAYS the first lines.
2. Provenance block (`GOCORTEX_SKILLS_*`).
3. Identity: vendor / product / dataset / one-paragraph description.
4. ALERT / EVENT FIELD MAPPING (`->` arrows) + any advisory NOTES + NOT MAPPED list with reasons.
5. REVIEW UNMODELLED query.
6. RAISE SKILL ISSUES pointer.

Then the `[MODEL: ...]` body. The sections in detail:

- A MAPPED-header comment block (mandatory). Vendor / product / dataset / one-paragraph description / Alert-or-Event Field Mapping with `->` arrows / NOT MAPPED list with reasons. The SPDX licence sits at the very TOP of this block (never at the bottom). See [assets/modeling_header_template.xql](assets/modeling_header_template.xql).
- A provenance block (mandatory), emitted verbatim as comment lines directly under the SPDX header so a script can grep it. Fill `GOCORTEX_SKILLS_MODEL` with the model id that authored the rule, `GOCORTEX_SKILLS_SKILL_NAME` / `GOCORTEX_SKILLS_SKILL_VERSION` from this skill's frontmatter (`cortex-platform-xdm-author` / `1.8.1`), `GOCORTEX_SKILLS_SKILL_WARNING_COUNT` with the advisory count from the final `scripts/lint_rule.py` run, and `GOCORTEX_SKILLS_SOURCE_BASIS` with `"spec-backed"` when a source reference (OpenAPI spec, vendor mnemonic doc, ...) informed the mapping or `"sample-only"` when only the raw sample was available (see workflow step 3):
  ```
  // Generated via
  // GOCORTEX_SKILLS_MODEL="<model id>"
  // GOCORTEX_SKILLS_SKILL_NAME="cortex-platform-xdm-author"
  // GOCORTEX_SKILLS_SKILL_VERSION="1.8.1"
  // GOCORTEX_SKILLS_SKILL_WARNING_COUNT="<lint warning count>"
  // GOCORTEX_SKILLS_SOURCE_BASIS="<spec-backed | sample-only>"
  ```
  `scripts/scaffold_rule.py` emits this automatically (name / version from SKILL.md, model and count from the build environment or its self-lint); when hand-authoring, add it yourself.
- The commented REVIEW UNMODELLED query (mandatory), placed as the second-to-last section, so unclassified records are discoverable -- see [references/record-classification.md](references/record-classification.md).
- A RAISE SKILL ISSUES pointer (mandatory), the LAST comment section, inviting the user to report a mis-mapping and include the REVIEW UNMODELLED output:
  ```
  // RAISE SKILL ISSUES -- if this rule mis-modelled something, please open
  // an issue and include the REVIEW UNMODELLED output above:
  //   https://github.com/gocortexio/skills/issues
  ```
- A `[MODEL: dataset=<vendor>_<product>_raw]` block in the three-stage shape: `filter` -> `alter` (extract) -> `alter` (assign).

## Authoring workflow

Full long-form in [references/workflow.md](references/workflow.md). Quick reference:

1. Confirm sample present. If not, ask for one.
2. Profile the sample with `python3 scripts/profile_log.py "<path/to/sample>"`. The script detects the format, walks each record into leaf paths (including `transactions[].http.method` array shapes and `{name, value}` header-pair arrays), infers field types, computes per-field null rates, flags every object-array's discriminator key, attaches ranked XDM candidates per field, and emits a `recommended_pattern` block. JSON worksheet by default; `--format text` for a table. If the script cannot run, fall back to the manual analysis in [references/workflow.md](references/workflow.md) Step 2.
3. Ask for the source reference (soft gate, skippable). After profiling you know `detected_format`, so ask the user once for the format-matched reference that gives the fields meaning, then proceed either way:
   - JSON / JSONL -> the OpenAPI / JSON Schema spec or API field docs (best signal: names, datatypes incl. array vs scalar, enums, which fields are identity / auth).
   - syslog / positional -> the vendor message / mnemonic reference (decodes `%FAC-SEV-MNEMONIC`, positional fields, severity) -- and confirm whether the source can arrive relay-prepended.
   - CEF / LEEF -> the vendor's extension dictionary. CSV / TSV -> the column dictionary.
   Given a link, fetch and mine it; given pasted text or a file, read it. If none is available, proceed with the sample alone -- do NOT block. Record the basis in the provenance block: `GOCORTEX_SKILLS_SOURCE_BASIS = "spec-backed"` when a reference informed the mapping, `"sample-only"` otherwise (a sample-only rule is lower-confidence and worth closer review). If you cannot ask (non-interactive), proceed sample-only and mark it.
4. Pick the extraction pattern. The profiler's `recommended_pattern` already maps `detected_format` and the object-array discriminators onto the decision tree below; confirm it against [references/extraction-patterns.md](references/extraction-patterns.md):
   - `_raw_log` contains JSON string -> A or C
   - `_raw_log` contains syslog / text -> B (if it opens with a `<NNN>` priority token, parse the Stage 0 envelope first -- see [references/syslog-envelope.md](references/syslog-envelope.md) -- then apply B to the payload)
   - `_raw_log` is null, fields are pre-parsed top-level columns -> D
   - object-array with a discriminator -> D' projection per discriminator value
5. Look up XDM targets via `python3 scripts/lookup_anchor.py <vendor_field_name>`. Treat frequency `>= 10` as a strong match, `3 - 9` as the default inclusion gate, `1 - 2` as a candidate-only signal. A `0` result means no anchor PRECEDENT -- the index records what past rules mapped, it is NOT the schema. Do NOT conclude the field has no XDM home from a `0`: first grep [references/xdm-schema.md](references/xdm-schema.md) for the concept (`auth`, `mfa`, `host`, `process`, ...). Only document a field in NOT MAPPED when xdm-schema.md genuinely has no field for it. Example: `mfa_method` returns `0` anchors but `xdm.auth.mfa.method` exists. If the script is unreachable, grep `assets/field_anchors.json` directly.
6. Cross-reference types against [references/xdm-schema.md](references/xdm-schema.md) and apply the transformation patterns in [references/transformation-patterns.md](references/transformation-patterns.md): numeric coercion, companion pairs, array wrapping, banded scoring, one-sided actor mirroring, authentication / MFA mapping (`xdm.auth.mfa.method`, `xdm.auth.is_mfa_needed`, plus the `xdm.event.operation` classification via `XDM_CONST.OPERATION_TYPE_*`). When the profiler flags an authentication event, apply the full mandatory XDM field set in [references/authentication-mapping.md](references/authentication-mapping.md) (the linter raises the advisory WARN-042 for each mandatory field left unmapped). When it flags a network event, apply the mandatory set in [references/network-mapping.md](references/network-mapping.md) likewise (advisory WARN-043). The two are independent, and network is the foundational layer: IDS, WAF, proxy and similar profiles describe a network flow on top of their primary role, and an authentication event carrying the full transport tuple is also a network connection. A dual event takes BOTH sets, with the union of the story tags in ONE `xdm.event.tags = arraycreate(...)`. When it flags a process / command-execution event, apply the recommended `xdm.*.process.*` mapping in [references/process-mapping.md](references/process-mapping.md) (advisory WARN-044). This is a recommended set, not a mandatory story. AAA / network-device command accounting (a `cmd=` record) is a command execution, not authentication: map its command to `xdm.target.process.command_line` with `xdm.event.type` a process value, operation `OPERATION_TYPE_AUDIT` and no outcome, and do NOT tag it `EVENT_TAG_AUTHENTICATION` (only the AUTHEN login and AUTHOR authorization shapes are authentication). Classification is PER RECORD throughout: decide `xdm.event.type` and `xdm.event.tags` on each record via one `if()` over the closed six-member `EVENT_TAG` enum (ending with no default, so an unrecognised record gets blank tags), filter only `_raw_log != null`, and give any record you cannot classify the catch-all (`xdm.event.original_event_type = "GOCORTEX_UNMODELLED"`) plus the commented REVIEW UNMODELLED query, so a `datamodel` search returns the same row count as the raw dataset (see [references/record-classification.md](references/record-classification.md); WARN-045 flags an invented tag, WARN-046 a record-dropping filter).
7. Draft the rule. Three stages minimum: `filter` (null guard), `alter` (extract `tmp_temp` variables), `alter` (assign XDM fields). End with semicolon, no trailing comma. Prefix with the MAPPED-header block. By default, also emit a deterministic `xdm.event.description` summary built with `concat()` over the identifying fields (vendor action, subject, outcome, and so on) -- see [references/transformation-patterns.md](references/transformation-patterns.md) structured event description. This is an ADDITION to the structured XDM fields, never a substitute: map each value to its own field first, then summarise. Do not bury data in the description that belongs in a queryable field.
8. Lint. `python3 scripts/lint_rule.py <rule.xql>` runs the structural, schema-aware, and dataflow checks: ERR-009/010/011/012/013/014/015/016/017/018/019/020/024/025/027/028/029, WARN-014/015/017/018/035/037/038/039/040/041/042/043/044, plus the INFO-012 cascade hint and the INFO-013 over-mapping advisory. It reads the XDM schema and XDM_CONST lists from the references and runs a reach + array-typing pass, so the schema and dataflow checks happen offline.
9. Fix earliest-first. The earliest violation is almost always the root cause; the rest are cascade noise. See INFO-012 in [references/parser-idioms.md](references/parser-idioms.md).
10. Re-lint until clean, then emit the final output.

## Note on intermediate variables

Scratch temporaries use the `tmp_` prefix (`tmp_user`, `tmp_src_ip`, ...). The `_` prefix is reserved by the platform for internal / system-generated fields (`_raw_log`, `_time`, `_message`, ...), so a rule must never CREATE a `_`-prefixed field -- `lint_rule.py` raises ERR-028 if it does (reading `_raw_log` is fine). No explicit `| fields -...` cleanup stage is needed: a MODEL rule surfaces only `xdm.*` fields, so `tmp_` temporaries never reach the datamodel regardless of name; the linter therefore does NOT flag a missing cleanup stage (INFO-006). See [references/extraction-patterns.md](references/extraction-patterns.md) "A note on intermediate variables".

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
- Never assign a banned XDM field. A banned field is a REAL Cortex path that belongs to an internal or non-event data model (for example `xdm.*.cloud.source_type`, an XCloud asset attribute), so a MODEL rule that assigns it fails tenant validation with "not part of the selected data model" even though the path looks legitimate. The registry is [assets/banned_fields.json](assets/banned_fields.json) (each entry carries the reason and the correct alternative); the linter blocks any assignment as ERR-029. See [references/banned-fields.md](references/banned-fields.md).
- Never invent `XDM_CONST` values. Closed lists in [references/xdm-const.md](references/xdm-const.md). If no constant matches, OMIT the field and fall back to the String alternative per [references/pitfall-traps.md](references/pitfall-traps.md).
- Always map a const-typed enum over its COMPLETE set, never just the values the sample showed. `xdm.network.http.response_code` is the canonical case: it is const-typed over all 60 HTTP status codes, so cast the status to an integer and render the full crosswalk chain with `python3 scripts/http_status_map.py --render` -- a production source returns codes the sample never contained, and a partial hand-written chain silently drops them (WARN-048). The same principle holds for any const field whose full membership is known.
- For an endpoint / process / file / registry / image event (Linux commands, Windows events, Sysmon, EDR), classify on three fields, not one label: put the raw channel / source label in `xdm.event.type`, the per-record semantic name in `xdm.event.original_event_type`, and the precise verb in `xdm.event.operation` (a member of the 56-strong `XDM_CONST.OPERATION_TYPE_*` enum -- `PROCESS_CREATE`, `IMAGE_LOAD`, `REGISTRY_SET_VALUE`, `FILE_REMOVE`, `EXECUTION`, ...). Do NOT leave `xdm.event.operation` blank when a verb fits, and do NOT stuff a semantic string into `xdm.event.type`. Endpoint events carry blank `xdm.event.tags` -- there is no process story tag -- yet are still fully modelled, so they do NOT take the `GOCORTEX_UNMODELLED` catch-all. See [references/process-mapping.md](references/process-mapping.md).
- For a cloud audit source (AWS CloudTrail, Azure, GCP), DERIVE `xdm.event.operation` from the provider's action-naming convention (CloudTrail `eventName` prefix, Azure `operationName` suffix, GCP `methodName` verb) rather than hardcoding the handful of actions the sample showed -- and keep the raw action in `xdm.event.original_event_type`. Map `xdm.*.cloud.provider` reliably, and set `xdm.*.cloud.service` (`CLOUD_SERVICE_TYPE`) only on a confident known match; when the raw service name maps to no constant, keep it in `xdm.event.type` / `xdm.event.description` or the NOT MAPPED block. NEVER assign `xdm.*.cloud.source_type` -- it is a banned internal-only field (see the banned-field rule below). See [references/cloud-mapping.md](references/cloud-mapping.md).
- Never hardcode a value that came from the sample. A tenant URL path, hostname, IP, ID or product-specific token must NOT be baked into a `contains "..."` branch or an `= "..."` assignment -- that leaks customer-internal data into the rule and does not scale beyond what the sample happened to show (WARN-049). Extract the value dynamically (e.g. `arrayindex(regextract(<field>, "/([^/]+)/"), N)` for a path segment) or keep the raw value in a free-String XDM field. Only hardcode `XDM_CONST` members, the observer vendor / product identity, and well-known vendor-agnostic tokens (`kerberos`, `$`, ...). Never invent a classification the source does not define -- see [references/transformation-patterns.md](references/transformation-patterns.md) "Never hardcode sample-derived values".
- Never use infix arithmetic inside `alter`. Use `add()`, `subtract()`, `multiply()`, `divide()` -- see [references/parser-idioms.md](references/parser-idioms.md) (ERR-012).
- Never assign a raw numeric score to `xdm.alert.severity`. Apply banded scoring per [references/transformation-patterns.md](references/transformation-patterns.md).
- Never echo a log-level word into `xdm.alert.severity`. Words like `warning`, `error`, `notice`, `debug` are syslog levels, not severity bands. Band them to Informational / Low / Medium / High / Critical and map the raw level to `xdm.event.log_level` -- see [references/transformation-patterns.md](references/transformation-patterns.md) log-level vocabulary (WARN-037).
- Always end a categorical if-chain into a free-String XDM field that carries vendor text (`xdm.alert.subcategory`, `xdm.observer.action`, `xdm.alert.original_threat_name`, and similar) with a `tmp_field != null, tmp_field` passthrough, so an unmapped vendor value is preserved rather than silently nulled. This does NOT apply to closed-list `XDM_CONST` targets (omit the default -> null) nor to band-vocabulary fields like `xdm.alert.severity` (floor to a band, never echo raw).
- Always emit the MAPPED header. It is the required prefix for every rule -- see [references/modeling-rules.md](references/modeling-rules.md) and [assets/modeling_header_template.xql](assets/modeling_header_template.xql).
- Always use British English in comments (normalise, analyse, behaviour, colour).

## Mapping decision checklist

Run this before emitting, so the same log maps the same way every time. Each item is a deterministic rule, not a judgement call:

- Outcome only on a real result. Set `xdm.event.outcome` only when the log reports success / failure / blocked. A detection disposition (`alert`, `monitor`, `isolate`) is NOT an outcome -- keep it in `xdm.observer.action` (see transformation-patterns.md "Event outcome").
- Host + IP -> emit the address companion. When `xdm.<side>.host.hostname` and `xdm.<side>.ipv4` are both set, also set `xdm.<side>.host.ipv4_addresses = if(ip != null, arraycreate(ip), null)` (WARN-038).
- Syslog source -> parse the envelope (Stage 0) before the payload, and make it prepend-robust (HARD RULE). The same source arrives direct and behind a relay that prepends its own `<PRI>` header, so capture the envelope relay-aware (greedy `^.*` -> origin host + origin PRI) and anchor every payload field on its own token, never on `^` -- extraction must be identical for both arrival forms even if the sample showed only one. Verify a syslog rule against both a direct and a relay-prepended copy of the sample. Decode the priority into `xdm.event.log_level` / `xdm.alert.severity` as a fallback under the payload severity -- see [references/syslog-envelope.md](references/syslog-envelope.md) (WARN-040 vendor-anchored header, WARN-041 priority captured but never decoded, WARN-047 prepend-fragile body capture).
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
- [references/banned-fields.md](references/banned-fields.md) -- real Cortex paths a MODEL rule must never assign (internal / non-event data models; enforced by ERR-029 from [assets/banned_fields.json](assets/banned_fields.json))
- [references/extraction-patterns.md](references/extraction-patterns.md) -- A / B / C / D extraction patterns
- [references/extraction-recipes.md](references/extraction-recipes.md) -- verified regex recipes for common syslog / text / CEF / LEEF shapes (advisory starting points for Pattern B; each proven lint-clean and by the verifier)
- [references/syslog-envelope.md](references/syslog-envelope.md) -- Stage 0 transport layer for syslog sources (PRI-anchored host + priority decode)
- [references/transformation-patterns.md](references/transformation-patterns.md) -- coercion, companion pairs, banded scoring, mirroring
- [references/authentication-mapping.md](references/authentication-mapping.md) -- mandatory XDM field set for authentication events (auto-detected; advisory WARN-042)
- [references/network-mapping.md](references/network-mapping.md) -- mandatory XDM field set for network events (auto-detected; advisory WARN-043; dual-story tag union)
- [references/process-mapping.md](references/process-mapping.md) -- recommended XDM mapping for process / command-execution events (endpoint / EDR process starts, script runs, AAA command accounting; auto-detected, advisory WARN-044)
- [references/record-classification.md](references/record-classification.md) -- per-record classification of `xdm.event.type` / `xdm.event.tags` over the closed six-member EVENT_TAG enum, and the catch-all that keeps the datamodel row count equal to the raw count (advisory WARN-045 / WARN-046)
- [references/cloud-mapping.md](references/cloud-mapping.md) -- cloud audit-log mapping (AWS CloudTrail, Azure Activity / Entra sign-in, GCP Cloud Audit): provider / region / account entity, the per-provider action -> `OPERATION_TYPE` verb conventions, outcome derivation, cloud / saas / auth classification, and nested-JSON extraction
- [references/mitre-mapping.md](references/mitre-mapping.md) -- MITRE ATT&CK into the `xdm.alert.mitre_techniques` / `mitre_tactics` arrays: direct id/name mapping via the full authoritative crosswalk (`assets/mitre_crosswalk.json`, resolved by `scripts/mitre_map.py`), and high-confidence keyword -> tactic fuzzy mapping that collects EVERY matched tactic (multi-match); auto-detected by the profiler
- [references/pitfall-traps.md](references/pitfall-traps.md) -- non-existent paths, confused pairs
- [references/compatibility-notes.md](references/compatibility-notes.md) -- `_gc_raw` caveats, deprecated fields
- [references/failure-modes.md](references/failure-modes.md) -- "if you see this in your draft, stop and do that" empirical notes
- [references/worked-examples.md](references/worked-examples.md) -- index of fifteen end-to-end log-to-rule walkthroughs (patterns A-D', the syslog envelope, the authentication / network / AAA stories, endpoint telemetry for Sysmon / Windows 4688 / Linux, Windows logon + Kerberos, and cloud audit for AWS CloudTrail / Azure / GCP); each lives in its own file under [references/worked-examples/](references/worked-examples/) so you load only the pattern in front of you

## Scripts

All scripts are Python 3.9+ stdlib only -- no Node, no `pip install`, no network access. Run from the bundle root. The typical loop is profile -> scaffold -> lint -> verify.

- `python3 scripts/profile_log.py <sample>` -- static profiler for a raw vendor log sample. Detects format (JSON, JSONL, CEF, LEEF, syslog, key=value, CSV, TSV), walks each record into leaf paths (with `[]` markers and per-name entries for `{name, value}` header-pair arrays), infers types, computes per-field null rates, flags object-array discriminators, attaches ranked XDM candidates, and recommends an extraction pattern. JSON worksheet by default; `--format text` for a table. Exits 0 on success, 1 on argument error, 2 on unreadable or unparseable input.
- `python3 scripts/scaffold_rule.py <worksheet.json>` -- turns a profiler worksheet (path or `-` for stdin) into a complete, lint-clean starter MODEL rule: MAPPED header, extraction stage, and an XDM drain wired from the worksheet's anchor candidates. `--vendor` / `--product` / `--dataset` set the identity. Self-gates through the linter before printing.
- `python3 scripts/lookup_anchor.py <vendor_field_name>` -- ranked XDM target candidates from the field-anchor index. `--reverse <xdm.path>` lists the vendor synonyms that fill a target (top-down authoring); `--related <xdm.path>` lists companion / mirror fields. The index ships under `assets/field_anchors.json`.
- `python3 scripts/xdm_const_mapper.py --field <xdm.path> --values a,b,c` -- emits the `if()`-chain mapping vendor values to the field's XDM_CONST members (never invents a constant). `--banded` emits the paired severity / log-level chains for a score column.
- `python3 scripts/mitre_map.py --kind technique --ids T1078,T1059` -- maps MITRE technique / tactic IDs or `--names` to `XDM_CONST.MITRE_*` constants and emits the `arraymap` chain. Validated against the documented MITRE lists; unmapped inputs are reported, not invented.
- `python3 scripts/lint_rule.py <rule.xql>` -- the rule linter. Structural and parser-conformance checks (ERR-009/010/011/012/013/014/015/016/017/018/024/027, ERR-028 a scratch temp using the reserved `_` prefix instead of `tmp_`, WARN-015/017/018, INFO-012), schema-aware checks read from the references (ERR-020 invented path, ERR-029 banned internal-only field assigned (registry `assets/banned_fields.json`), WARN-014 quoted XDM_CONST, WARN-035 array-vs-scalar shape, WARN-037 log-level word in severity, WARN-038 missing host.ipv4_addresses companion, WARN-039 whole payload dumped into the description, WARN-040 vendor-anchored syslog header, WARN-041 syslog priority captured but never decoded, WARN-042 authentication-story mandatory set advisory, WARN-043 network-story mandatory set advisory, WARN-044 process / command-execution advisory -- the executable-parent misuse, WARN-045 invented EVENT_TAG outside the closed six-member enum, WARN-046 record-dropping content filter with no catch-all sentinel, WARN-047 prepend-fragile syslog body extraction anchored on `^` / a fixed offset instead of a payload token, WARN-048 incomplete HTTP response-code mapping (an `xdm.network.http.response_code` if()-chain covering fewer status codes than the authoritative crosswalk), WARN-049 hardcoded sample-derived customer literal (a path / host / IP / ID baked into a `contains` / `=` branch), WARN-050 endpoint event (a process / file / registry / module entity mapped) that never assigns `xdm.event.operation` a precise `OPERATION_TYPE` verb), dataflow checks over the rule's temps (ERR-019 unused temp -- a `tmp_` never referenced again -- a hard block on EVERY dataset, since Cortex rejects an unused field regardless of suffix; ERR-025 concat-hidden temp, still scoped to `_gc_raw`), and the INFO-013 over-mapping advisory (one temp across 3+ entity families). Exits 0 on clean, 1 if any error-severity violation fires. INFO-006 (cleanup stage) is intentionally not emitted -- see the note above.
- `python3 scripts/verify_rule.py <rule.xql> <sample.json>` -- evaluates the rule against the sample offline and prints the resulting `xdm.*` map per record, so you can confirm behaviour without a tenant. `--expect <expected.json>` diffs against expected output. Unsupported constructs are reported, not guessed.
- `python3 scripts/score_mappings.py --report` -- runs the author-curated mapping-accuracy corpus (`tests/corpus/mapping_matrix.json`: sample event -> the CORRECT XDM output) through the worked-example rules and reports per-source and overall field-for-field accuracy. The ground truth is authored from provider docs + the XDM schema, so the score measures correctness, not agreement with any content pack.

If the scripts cannot run (no Python available), treat the markdown references as the authoritative checklist: walk [references/parser-idioms.md](references/parser-idioms.md) (ERR-012 through ERR-019, plus idioms (xi) / (xii)), [references/modeling-rules.md](references/modeling-rules.md) (validation checklist), and [references/pitfall-traps.md](references/pitfall-traps.md) before emitting the rule.

## Bundle integrity tests

The bundle ships Python stdlib tests under [tests/](tests/). They cover JSON validity, SPDX-header presence, frontmatter shape, doc-to-schema consistency for every `xdm.*` and `XDM_CONST.*` cited in the references, ASCII-only and no-emphasis hygiene, the MAPPED-header template's required rows, and the linter's behaviour on a set of fixtures. Run from the bundle root:

```sh
python3 -m unittest discover -v -s tests
```

Python 3.9+ stdlib only. These tests cover the bundle itself. The path for linting user XQL rules is `python3 scripts/lint_rule.py`. See [tests/README.md](tests/README.md) for what each test guards.
