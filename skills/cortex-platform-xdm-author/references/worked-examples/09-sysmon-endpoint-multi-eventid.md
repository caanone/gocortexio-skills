<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Walkthrough 9 -- Sysmon endpoint telemetry, many EventIDs through one rule

Vendor / product: Microsoft / Sysmon (System Monitor). Dataset:
`microsoft_sysmon_raw`, JSON-bodied Windows event records (an `event_id`
discriminator plus an `event_data` container and the event `channel`).

What this walkthrough shows: an endpoint agent emits MANY record kinds from one
feed (process creation, registry changes, image loads, network connections,
...), and one MODEL rule normalises them through a shared assignment stage while
classifying PER RECORD on the endpoint model from
[process-mapping.md](../process-mapping.md): `xdm.event.type` = the channel,
`xdm.event.original_event_type` = the per-EventID semantic name, and
`xdm.event.operation` = the precise `XDM_CONST.OPERATION_TYPE_*` verb. Endpoint
records carry NO story tag (there is no process `EVENT_TAG`), so
`xdm.event.tags` is blank -- but a record it recognises is still fully modelled
and does NOT take the `GOCORTEX_UNMODELLED` catch-all; only an EventID the rule
does not yet handle does.

This walkthrough covers EventID 1 (process creation) and EventID 13 (registry
value set) end to end, with the catch-all proving an unhandled EventID still
produces a row. The same shape extends to 3 (network), 7 (image load), 11 (file
create), 22 (DNS), and the rest -- add a branch to each `if()`-chain.

## The endpoint classification model

Three independent fields, not one label:

| Field | Value | Why |
| --- | --- | --- |
| `xdm.event.type` | the raw `channel` | the source channel, not a semantic string |
| `xdm.event.original_event_type` | per-EventID name (`Process Create`, ...) | the human-readable record kind |
| `xdm.event.operation` | `OPERATION_TYPE_*` verb | where the meaning lives; the linter knows all 56 verbs |
| `xdm.event.tags` | blank | no process story tag exists; the record is still modelled |

## The full rule

```
[MODEL: dataset = microsoft_sysmon_raw]
filter
    _raw_log != null
| alter
    tmp_channel     = json_extract_scalar(_raw_log, "$.channel"),
    tmp_eid         = to_integer(to_number(json_extract_scalar(_raw_log, "$.event_id"))),
    tmp_utc         = json_extract_scalar(_raw_log, "$.event_data.UtcTime"),
    tmp_image       = json_extract_scalar(_raw_log, "$.event_data.Image"),
    tmp_cmd         = json_extract_scalar(_raw_log, "$.event_data.CommandLine"),
    tmp_pid         = json_extract_scalar(_raw_log, "$.event_data.ProcessId"),
    tmp_ppid        = json_extract_scalar(_raw_log, "$.event_data.ParentProcessId"),
    tmp_user        = json_extract_scalar(_raw_log, "$.event_data.User"),
    tmp_hashes      = json_extract_scalar(_raw_log, "$.event_data.Hashes"),
    tmp_integrity   = json_extract_scalar(_raw_log, "$.event_data.IntegrityLevel"),
    tmp_target_obj  = json_extract_scalar(_raw_log, "$.event_data.TargetObject"),
    tmp_details     = json_extract_scalar(_raw_log, "$.event_data.Details"),
    tmp_reg_type    = json_extract_scalar(_raw_log, "$.event_data.EventType")
| alter
    tmp_il = lowercase(to_string(tmp_integrity))
| alter
    xdm.event.type = tmp_channel,
    xdm.event.id = to_string(tmp_eid),
    xdm.event.original_event_type = if(
        tmp_eid = 1,  "Process Create",
        tmp_eid = 13, "Registry value set",
        "GOCORTEX_UNMODELLED"),
    xdm.event.operation = if(
        tmp_eid = 1,  XDM_CONST.OPERATION_TYPE_PROCESS_CREATE,
        tmp_eid = 13, XDM_CONST.OPERATION_TYPE_REGISTRY_SET_VALUE),
    xdm.event.tags = null,
    xdm.source.host.os_family = XDM_CONST.OS_FAMILY_WINDOWS,
    xdm.source.process.executable.path = tmp_image,
    xdm.source.process.name = arrayindex(regextract(to_string(tmp_image), "([^\\\\/]+)$"), 0),
    xdm.source.process.command_line = tmp_cmd,
    xdm.source.process.pid = to_integer(to_number(tmp_pid)),
    xdm.source.process.parent_id = tmp_ppid,
    xdm.source.process.executable.sha256 = arrayindex(regextract(to_string(tmp_hashes), "SHA256=([0-9A-Fa-f]{64})"), 0),
    xdm.source.process.executable.md5 = arrayindex(regextract(to_string(tmp_hashes), "MD5=([0-9A-Fa-f]{32})"), 0),
    xdm.source.process.integrity_level = if(
        tmp_il contains "untrusted", 0,
        tmp_il contains "low", 1,
        tmp_il contains "medium", 2,
        tmp_il contains "high", 3,
        tmp_il contains "system", 4),
    xdm.source.user.username = arrayindex(regextract(to_string(tmp_user), "\\\\([^\\\\]+)$"), 0),
    xdm.source.user.domain = arrayindex(regextract(to_string(tmp_user), "^([^\\\\]+)\\\\"), 0),
    xdm.target.registry.key = tmp_target_obj,
    xdm.target.registry.value = tmp_details,
    xdm.event.outcome_reason = tmp_reg_type,
    xdm.event.description = concat("sysmon eid ", to_string(tmp_eid), " ", coalesce(tmp_cmd, tmp_target_obj, tmp_utc))
;
// REVIEW UNMODELLED -- list records this rule could not classify and
// grow it to cover them:
//   datamodel dataset = microsoft_sysmon_raw
//   | filter xdm.event.original_event_type = "GOCORTEX_UNMODELLED"
//   | fields xdm.event.original_event_type, microsoft_sysmon_raw._raw_log
//
// RAISE SKILL ISSUES -- report a mis-mapping (include the REVIEW
// UNMODELLED output above): https://github.com/gocortexio/skills/issues
```

## Key decisions worth copying

- The channel / verb model. `xdm.event.type` is the raw `channel`, not a
  hand-written label; the per-EventID name goes to
  `xdm.event.original_event_type`; and the meaning is the
  `xdm.event.operation` verb (`OPERATION_TYPE_PROCESS_CREATE`,
  `OPERATION_TYPE_REGISTRY_SET_VALUE`). Every verb resolves because the full
  56-member `OPERATION_TYPE` enum is documented in
  [xdm-const.md](../xdm-const.md).
- Endpoint records carry blank tags. There is no process story tag, so
  `xdm.event.tags = null`. A recognised record (EventID 1 / 13) is still fully
  modelled; only an unhandled EventID falls to the
  `GOCORTEX_UNMODELLED` catch-all in `original_event_type`. Nothing is filtered,
  so the datamodel row count equals the raw count.
- One shared assignment stage. Both EventIDs draw from the same extraction: a
  registry record simply leaves the process temps null and vice versa, so a
  process record has null `xdm.target.registry.key` and a registry record has
  null `xdm.source.process.*`. No per-EventID pipeline duplication.
- Map the image to a LEAF. `xdm.source.process.executable.path = tmp_image`
  and the process name is the last path segment; never assign the
  `xdm.source.process.executable` parent (typed Number).
- Hashes from one blob. Sysmon packs every algorithm into a single `Hashes`
  string (`MD5=...,SHA256=...`); `regextract` pulls each out by its label.
- Integrity level is an integer. `xdm.*.process.integrity_level` is a Number,
  so the Windows integrity word maps to 0..4 -- never an `XDM_CONST` token.
- `DOMAIN\user` split. The `User` field is `DOMAIN\name`; `regextract` splits
  the domain and the username. (These regexes end in an escaped backslash --
  verified with `verify_rule.py`.)

## NOT MAPPED, with reasons

```
NOT MAPPED
  event_data.ParentImage / ParentCommandLine -- xdm.source.process.parent_process.*
                      does NOT exist in the schema; only parent_id (mapped) has
                      a home. Retain the parent image in the raw record.
  event_data.LogonGuid / LogonId -- session correlation with no endpoint
                      home on a process record; revisit under the Windows
                      logon story
  event_data.RuleName -- Sysmon config rule label, not xdm.network.rule on a
                      non-network record
  event_data.Company / Product / Description -- PE version metadata; no XDM
                      home, keep in the raw record
```

## Checklist

```
[ ] only filter is _raw_log != null (nothing dropped)
[ ] event.type = channel; original_event_type = per-EventID name; operation = OPERATION_TYPE verb
[ ] event.tags blank (no process story tag); recognised records NOT catch-alled
[ ] unhandled EventID -> GOCORTEX_UNMODELLED with the REVIEW UNMODELLED query
[ ] image mapped to executable.path leaf, never the Number parent
[ ] SHA256/MD5 pulled from the single Hashes blob by label
[ ] integrity_level is a 0..4 integer, not a constant
[ ] DOMAIN\user split; proven with verify_rule.py on EventID 1 and 13
```
