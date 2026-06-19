<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Data model rules (`[MODEL: dataset=..._raw]`)

The data model rule reads from a `_raw` dataset and writes XDM (eXtended Data Model) fields that downstream correlations, searches, and dashboards depend on. This is the only rule type this skill covers.

## Header

```
[MODEL: dataset=acme_firewall_raw]
```

- Unquoted dataset name. WARN-015 fires if you quote it.
- Dataset name must end in `_raw`.
- No `vendor` or `product` keys in the header. Those are written as XDM fields inside the rule body (`xdm.observer.vendor`, `xdm.observer.product`).
- Vendor / product / dataset cannot be derived from the log body. Infer them from the product or API title and flag them as tenant-adjustable in the MAPPED header, naming the three exact touch-points a reviewer edits: `xdm.observer.vendor`, `xdm.observer.product`, and the `[MODEL: dataset=...]` header. Make the edit trivial -- the reviewer should not have to hunt for them.

## Stage order

```
[MODEL: dataset=acme_firewall_raw]
filter <null_guard_condition>
| alter
    <extract temporary fields from raw log>
| alter
    <derive composite fields, banded scores, etc.>
| alter
    <assign XDM fields using the extracted temps>
;
```

- First stage after the header is `filter` with NO leading pipe (WARN-017 fires on a leading pipe). All subsequent stages use a leading pipe.
- Use multiple `alter` stages: one for extraction, optionally one for derivation, one for XDM assignment. This respects idiom (xi) (no sibling references inside a single `alter` -- see [parser-idioms.md](parser-idioms.md)).
- Rule MUST end with a semicolon (ERR-009). The last assignment before the semicolon must NOT have a trailing comma (ERR-010).
- The `filter` must NOT be a no-op tautology (see "No no-op leading filter stages" in [pitfall-traps.md](pitfall-traps.md)).

## Extraction strategy decision tree

Use this to pick `json_extract_scalar` vs arrow vs `split` / `regextract`:

| Log shape | Use |
| --- | --- |
| `_raw_log` is valid JSON | `json_extract_scalar(_raw_log, "$.path")` |
| `_raw_log` is empty, top-level columns hold JSON strings | `json_extract_scalar(to_string(column_name), "$.path")` |
| `_raw_log` is empty, fields are direct top-level columns | Use column names directly (`senderIp`, `Subject`) |
| `_raw_log` contains syslog-wrapped positional data | `regextract()` to strip the syslog prefix, then `split()` + `arrayindex()` |
| Data is in label/value array pairs | `regextract()` with a pattern targeting the label/value structure |
| Top-level column holds a parsed JSON object (not a string) | Arrow operator: `column -> Path.Field` |

See [extraction-patterns.md](extraction-patterns.md) for the four canonical extraction patterns (A/B/C/D) with full vendor exemplars.

## XDM mapping priority

Assign in this order. Earlier categories first, since later ones often depend on them:

1. Observer identity: `xdm.observer.vendor` and `xdm.observer.product` (hardcoded strings).
2. Event classification: `xdm.event.type` -- normalised category: `"ALERT"`, `"NETWORK"`, `"AUTH"`, `"EMAIL"`, `"FILE"`, `"PROCESS"`, `"ENDPOINT_ACTIVITY"`, `"AUDIT"`. Then `xdm.event.id`, `xdm.event.original_event_type`, `xdm.event.description`, `xdm.event.outcome`, and `xdm.event.operation` (`XDM_CONST.OPERATION_TYPE_*` -- e.g. `OPERATION_TYPE_AUTH_MFA` / `OPERATION_TYPE_AUTH_LOGIN` for AUTH events, `OPERATION_TYPE_AUDIT` for audit trails; omit only when no constant fits).
3. Source and target identities: IPs, hostnames, ports, users.
4. Domain-specific fields: `xdm.alert.`, `xdm.email.`, `xdm.network.`, `xdm.auth.`.
5. Intermediate fields: for proxy or gateway devices between source and target.

## Mandatory validation checklist

The bundled `scripts/lint_rule.py` covers the syntactic subset of these checks (ERR-012 through ERR-018, ERR-024, INFO-012). Dataflow- and schema-dependent items such as WARN-019 unused-variable and ERR-025 must be reviewed by eye against the list below before invoking the linter.

- Every `_temp` variable is consumed in an XDM assignment (WARN-019; unused = BLOCKING error, see ERR-019 in [parser-idioms.md](parser-idioms.md)).
- `xdm.observer.vendor` and `xdm.observer.product` are set (hardcoded strings).
- `xdm.event.type` is set to a normalised category string.
- `XDM_CONST` values are NOT quoted (WARN-014).
- Dataset name is NOT quoted in the `MODEL` header (WARN-015).
- No leading pipe before the first stage after the `MODEL` header (WARN-017).
- Numeric comparisons use numeric literals (`severity = 4` not `severity = "4"`).
- Array-type XDM fields use `arraycreate()` (WARN-020).
- `to_string()` wraps any `arrayindex()` output before passing to `split()` or `regextract()`.
- No self-referencing XDM fields (`xdm.x = coalesce(xdm.x, _y)` is INVALID, ERR-011).
- No chained arrow operators (`column -> field -> subfield` is INVALID; use `json_extract_scalar`).
- Rule ends with a semicolon (ERR-009). No trailing comma before the semicolon (ERR-010).
- A null-guard `filter` is present as the first stage (and is NOT a no-op tautology -- see "No no-op leading filter stages" in [pitfall-traps.md](pitfall-traps.md)).
- Every XDM field path exists in [xdm-schema.md](xdm-schema.md) (WARN-010).
- `_time` is NOT assigned in MODEL rules (WARN-018). Cortex sets it automatically; `_time` belongs to INGEST (parsing) rules.
- All [parser-idioms.md](parser-idioms.md) checks pass (ERR-012 through ERR-019, plus the (xi) / (xii) idioms).

## `_gc_raw` datasets

If the dataset name ends in `_gc_raw` (a GoCortex-specific raw dataset), extra constraints apply. See [compatibility-notes.md](compatibility-notes.md). Most importantly: `xdm.alert.mitre_techniques` and `xdm.session_context_id` are validator-flagged on `_gc_raw` and should not be set unless the vendor data explicitly justifies them.

## MAPPED-header comment block (mandatory)

Every model rule MUST be prefixed with a MAPPED-header comment block. See [../assets/modeling_header_template.xql](../assets/modeling_header_template.xql) for the template.
