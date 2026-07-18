<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Walkthrough 10 -- Windows Security 4688, a new process created

Vendor / product: Microsoft / Windows Security auditing. Dataset:
`microsoft_windows_raw`, JSON-bodied Windows event records (an `event_id`
discriminator plus an `event_data` container and the event `channel`).

What this walkthrough shows: the classic Windows Security process-creation
event (4688) mapped on the endpoint model from
[process-mapping.md](../process-mapping.md). The new process is the source
process; the subject (the account that created it) is the source user. As with
Sysmon (walkthrough 9), classify on three fields -- `xdm.event.type` = the
channel (`Security`), `xdm.event.original_event_type` = the per-EventID name,
and `xdm.event.operation` = `XDM_CONST.OPERATION_TYPE_PROCESS_CREATE` -- and the
record carries no story tag. Add a branch per further EventID (4689 process
exit -> `PROCESS_TERMINATE`, 4657 registry -> `REGISTRY_SET_VALUE`, ...).

## The full rule

```
[MODEL: dataset = microsoft_windows_raw]
filter
    _raw_log != null
| alter
    tmp_channel   = json_extract_scalar(_raw_log, "$.channel"),
    tmp_eid       = to_integer(to_number(json_extract_scalar(_raw_log, "$.event_id"))),
    tmp_newimage  = json_extract_scalar(_raw_log, "$.event_data.NewProcessName"),
    tmp_cmd       = json_extract_scalar(_raw_log, "$.event_data.CommandLine"),
    tmp_subj_user = json_extract_scalar(_raw_log, "$.event_data.SubjectUserName"),
    tmp_subj_dom  = json_extract_scalar(_raw_log, "$.event_data.SubjectDomainName"),
    tmp_parent    = json_extract_scalar(_raw_log, "$.event_data.ParentProcessName")
| alter
    xdm.event.type = tmp_channel,
    xdm.event.id = to_string(tmp_eid),
    xdm.event.original_event_type = if(
        tmp_eid = 4688, "A new process has been created",
        "GOCORTEX_UNMODELLED"),
    xdm.event.operation = if(
        tmp_eid = 4688, XDM_CONST.OPERATION_TYPE_PROCESS_CREATE),
    xdm.event.tags = null,
    xdm.source.host.os_family = XDM_CONST.OS_FAMILY_WINDOWS,
    xdm.source.process.executable.path = tmp_newimage,
    xdm.source.process.name = arrayindex(regextract(to_string(tmp_newimage), "([^\\\\/]+)$"), 0),
    xdm.source.process.command_line = tmp_cmd,
    xdm.source.user.username = tmp_subj_user,
    xdm.source.user.domain = tmp_subj_dom,
    xdm.event.description = concat(
        "windows ", to_string(tmp_eid), ": ",
        coalesce(tmp_newimage, "process"),
        if(tmp_parent != null, concat(" (parent ", tmp_parent, ")"), ""))
;
// REVIEW UNMODELLED -- list records this rule could not classify and
// grow it to cover them:
//   datamodel dataset = microsoft_windows_raw
//   | filter xdm.event.original_event_type = "GOCORTEX_UNMODELLED"
//   | fields xdm.event.original_event_type, microsoft_windows_raw._raw_log
//
// RAISE SKILL ISSUES -- report a mis-mapping (include the REVIEW
// UNMODELLED output above): https://github.com/gocortexio/skills/issues
```

## Key decisions worth copying

- The new process is the source. 4688 records the process that was created;
  map it to `xdm.source.process.*` (matching the Sysmon convention). The
  subject account that created it is `xdm.source.user.*`.
- Subject user is pre-split. Unlike Sysmon's `DOMAIN\user`, 4688 provides
  `SubjectUserName` and `SubjectDomainName` as separate fields -- map each
  directly, no regex split.
- The verb, not a label. `xdm.event.operation = OPERATION_TYPE_PROCESS_CREATE`
  carries the meaning; `xdm.event.type` stays the raw `Security` channel and
  `xdm.event.original_event_type` the readable record name.
- Blank tags, real model. No process story tag exists, so `xdm.event.tags`
  is null; a recognised 4688 is still fully modelled and does NOT take the
  `GOCORTEX_UNMODELLED` catch-all.

## NOT MAPPED, with reasons

```
NOT MAPPED
  event_data.NewProcessId / ProcessId -- 4688 encodes both as HEX ("0x1a4").
                      xdm.*.process.pid is a Number; convert the hex before
                      mapping (out of scope here) rather than storing "0x1a4"
  event_data.ParentProcessName -- xdm.source.process.parent_process.* does not
                      exist; kept in the description for context
  event_data.TokenElevationType / MandatoryLabel -- elevation SID / token
                      taxonomy with no XDM process leaf; retain in the raw record
  event_data.TargetUserName -- for 4688 this mirrors the subject; only map a
                      distinct target identity when the event has one
```

## Checklist

```
[ ] only filter is _raw_log != null (nothing dropped)
[ ] new process -> xdm.source.process.*; subject -> xdm.source.user.*
[ ] event.type = channel; original_event_type = per-EventID name; operation = PROCESS_CREATE
[ ] event.tags blank; recognised 4688 NOT catch-alled; unknown EventID -> GOCORTEX_UNMODELLED
[ ] image mapped to executable.path leaf, never the Number parent
[ ] hex process ids handled or deliberately left unmapped (never stored as "0x..")
[ ] proven with verify_rule.py on a 4688 record
```
