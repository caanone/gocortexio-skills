<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Banned XDM fields -- real paths a MODEL rule must never assign

A banned field is different from an invented one. An invented path (ERR-020)
does not exist anywhere in Cortex. A banned field is a GENUINE Cortex XDM path
that appears in vendor documentation, but belongs to an internal or non-event
data model, so a `[MODEL: ...]` rule that assigns it fails tenant validation
with:

```
<path> is not part of the selected data model
```

The path looks legitimate in every offline check that only asks "is this a
real field?", which is exactly why the ban list exists: these fields must be
rejected by name, with the reason recorded.

## Machine-readable registry

The authoritative list ships as [../assets/banned_fields.json](../assets/banned_fields.json).
Each entry carries:

- `path` -- the exact `xdm.*` path.
- `reason` -- why the field is off-limits (which data model owns it).
- `alternative` -- what to do instead.

The linter loads the registry and raises ERR-029 (error severity, blocks the
rule) on any assignment to a banned path. Adding a new entry to the JSON is
the complete change: the linter and the bundle's reference-integrity test
enforce it automatically from there. Keep the table below in sync with the
JSON (a bundle test asserts the two match).

## Current banned fields

| Path | Why | Instead |
| --- | --- | --- |
| `xdm.source.cloud.source_type` | Internal-only XCloud asset-inventory attribute: the asset type of a cloud asset (example values `t2.micro`, `t3.medium`, `gp2`, `gp3`). Not part of any event/log data model. | Map `xdm.source.cloud.provider` reliably; set `xdm.source.cloud.service` (CLOUD_SERVICE_TYPE) only on a confident known match; otherwise record the raw service name in the NOT MAPPED block, `xdm.event.type` or `xdm.event.description`. |
| `xdm.target.cloud.source_type` | Same XCloud asset attribute on the target entity. | Same as the source-side guidance, on the target fields. |
| `xdm.intermediate.cloud.source_type` | Same XCloud asset attribute on the intermediate entity. | Same as the source-side guidance, on the intermediate fields. |

## How a field earns a place here

1. A rule assigning the field fails tenant validation with "not part of the
   selected data model" (or equivalent), despite the path appearing in the
   upstream schema documentation.
2. The failure is confirmed against a real tenant, not inferred from a
   review alone.
3. The entry lands in `assets/banned_fields.json` with the reason and the
   alternative, and the row is added to the table above.

The upstream schema documentation flattens several Cortex data models into
one field list, so more internal-only fields may surface over time. When one
does, add it to the registry -- do not re-add it to
[xdm-schema.md](xdm-schema.md), which lists only fields a MODEL rule may
legitimately assign.
