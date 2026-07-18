<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Endpoint, process and command-execution mapping

Endpoint telemetry describes what happened on a host: a process starting or
stopping, a command being run, an image / DLL / shared object loading, a file
created / written / deleted, or a registry key / value changing. This covers
local Linux commands (shell, `sudo`, auditd), Windows Security events
(4688 process creation, etc.), Sysmon (EventID 1/3/7/11/12/13/22/...), and EDR
process telemetry. These map to the `xdm.*.process.*`, `xdm.target.file(_before).*`,
`xdm.target.registry(_before).*` and `xdm.target.module.*` families.

This is a RECOMMENDED mapping set, not a mandatory story. There is no process
`EVENT_TAG`, so there is no mandatory-field gate here -- the linter raises the
advisory WARN-044 to suggest companion fields, never to block. Map what the log
provides.

## The endpoint classification model (channel / semantic / verb)

Endpoint sources do not fit the story-tag model. Classify each record on three
independent fields, not by stuffing a label into `xdm.event.type`:

- `xdm.event.type` = the raw channel or source label -- the Windows channel
  (e.g. `Security`, `Microsoft-Windows-Sysmon/Operational`), the syslog
  program / tag, or a stable source label. It is NOT a hand-written semantic
  string like `"process creation"`.
- `xdm.event.original_event_type` = the per-record semantic name -- the vendor
  action / task / event name (`coalesce(tmp_action, tmp_task, tmp_event_name)`),
  e.g. `Process Create`, `Registry value set`, `execve`.
- `xdm.event.operation` = `XDM_CONST.OPERATION_TYPE_<verb>` -- the precise verb.
  This is where the meaning lives (see the derivation table below).
- `xdm.event.tags` = blank. The six `EVENT_TAG` story markers (authentication,
  network, cloud, saas, onprem, vpn) have NO process / file / registry member,
  so an endpoint event legitimately carries no tag.

Important: a Sysmon process-create event is fully modelled (operation + process
fields are set) even though it has no tag, so it does NOT get the
`GOCORTEX_UNMODELLED` catch-all. That sentinel is only for a record you cannot
classify at all -- see [record-classification.md](record-classification.md). A
record you understood but which simply has no story tag is modelled, not
unmodelled.

An `event_id` is only meaningful WITHIN its channel / provider. The same number
means different things in different providers: Sysmon EventID 12 / 13 are
registry create / value-set, but in `Microsoft-Windows-Kernel-General` EventID
12 / 13 are OS startup / shutdown. So never key `xdm.event.operation` or
`xdm.event.original_event_type` on `event_id` alone -- scope the `if()`-chain to
one provider per dataset (or gate it on the channel / provider as well as the
id) so a colliding number from another provider cannot be mis-classified.

## Actor vs target

- The process that ACTED (the running program, the session issuing the command)
  is the source: `xdm.source.process.*`.
- The process being ACTED UPON (a child that was terminated, a target of process
  access / remote-thread injection) is the target: `xdm.target.process.*`.
- For a local endpoint / EDR process, the command the process ran is
  `xdm.source.process.command_line`. Use `xdm.target.process.command_line` for a
  process the event acts upon (a child launched or terminated).

## Process family (map when present)

| XDM target | Notes |
| --- | --- |
| `xdm.source.process.name` | Short process / image name (`sshd`, `powershell.exe`). |
| `xdm.source.process.pid` | Process id. Number: `to_integer(to_number(...))`. |
| `xdm.source.process.parent_id` | Parent process id. String. |
| `xdm.source.process.command_line` | Full command line the process ran. |
| `xdm.source.process.executable.path` | Full path to the image on disk. |
| `xdm.source.process.executable.filename` | Image filename only. |
| `xdm.source.process.executable.directory` | Directory of the image. |
| `xdm.source.process.executable.md5` | Image MD5 hash. |
| `xdm.source.process.executable.sha256` | Image SHA-256 hash. |
| `xdm.source.process.executable.signer` | Code-signing signer. |
| `xdm.source.process.executable.is_signed` | Boolean. |
| `xdm.source.process.executable.signature_status` | `XDM_CONST.SIGNATURE_STATUS_*`. |
| `xdm.source.process.integrity_level` | Number 0..4 (see integrity level below). |
| `xdm.source.process.is_injected` | Boolean (Sysmon 25 process tampering). |
| `xdm.source.user.username` / `xdm.source.user.domain` | The acting user. |

The target family mirrors the source family; use `xdm.target.process.*` for the
process acted upon.

Guardrail: never assign a value to `xdm.source.process.executable` (or
`xdm.target.process.executable`) directly -- that path is typed Number, a parent
node, not the image name. Map the leaves (`executable.path`,
`executable.filename`, ...) instead.

## Operation verb: derive the precise OPERATION_TYPE

`xdm.event.operation` is a closed `XDM_CONST.OPERATION_TYPE_*` enum with 56
members (see [xdm-const.md](xdm-const.md)). For an endpoint event, map the most
specific verb the record supports -- do NOT leave the field blank when a member
fits. Pick from the vendor action / EventID:

| Record kind (vendor / EventID) | `xdm.event.operation` |
| --- | --- |
| Process creation (Sysmon 1, Windows 4688, Linux `execve` SYSCALL) | `OPERATION_TYPE_PROCESS_CREATE` |
| Process start where create semantics are not distinguished | `OPERATION_TYPE_PROCESS_START` |
| Process terminated (Sysmon 5) | `OPERATION_TYPE_PROCESS_TERMINATE` |
| Image / DLL loaded (Sysmon 7), driver loaded (Sysmon 6) | `OPERATION_TYPE_IMAGE_LOAD` |
| Image unloaded | `OPERATION_TYPE_IMAGE_UNLOAD` |
| File created (Sysmon 11) | `OPERATION_TYPE_FILE_CREATE` |
| File written / stream-hash (Sysmon 15) | `OPERATION_TYPE_FILE_WRITE` |
| File deleted (Sysmon 23 / 26) | `OPERATION_TYPE_FILE_REMOVE` |
| File renamed | `OPERATION_TYPE_FILE_RENAME` |
| Registry key created (Sysmon 12 CreateKey) | `OPERATION_TYPE_REGISTRY_CREATE_KEY` |
| Registry key deleted (Sysmon 12 DeleteKey) | `OPERATION_TYPE_REGISTRY_DELETE_KEY` |
| Registry value deleted (Sysmon 12 DeleteValue) | `OPERATION_TYPE_REGISTRY_DELETE_VALUE` |
| Registry value set (Sysmon 13) | `OPERATION_TYPE_REGISTRY_SET_VALUE` |
| Registry key / value renamed (Sysmon 14) | `OPERATION_TYPE_REGISTRY_RENAME_KEY` |
| A bare interactive / shell command with no finer semantics | `OPERATION_TYPE_EXECUTION` |
| A configuration command on a device | `OPERATION_TYPE_CONFIG_CHANGE` |
| AAA / network-device command accounting (`cmd=`) | `OPERATION_TYPE_AUDIT` |

Rule of thumb: choose the most specific verb the record supports; fall back to
`OPERATION_TYPE_EXECUTION` only for a plain command run with no create / terminate
semantics; leave `xdm.event.operation` unset ONLY when nothing in the enum
applies. (Earlier guidance said to leave it unmapped because "no command-
execution member exists" -- that was wrong; `OPERATION_TYPE_EXECUTION` and the
`PROCESS_*` verbs exist.)

## File family

For a file event, map `xdm.target.file.*` (the file acted upon):
`path`, `filename`, `directory`, `extension`, `md5`, `sha256`, `signer`,
`is_signed`, `signature_status`, `size`. For a rename, put the prior name in
`xdm.target.file_before.*` (e.g. `xdm.target.file_before.filename`).

## Registry family

For a registry event, map `xdm.target.registry.*`: `key`, `value`, `data`,
`value_type` (`XDM_CONST.REGISTRY_VALUE_TYPE_*`). On a value change / rename,
the prior state goes in `xdm.target.registry_before.*` (e.g.
`xdm.target.registry_before.value`). The Sysmon `TargetObject` maps to
`xdm.target.registry.key`, and `Details` to `xdm.target.registry.value`.

## Module / image family

For an image / DLL / driver load (Sysmon 6 / 7), map `xdm.target.module.*`:
`path`, `filename`, `directory`, `md5`, `sha256`, `signer`, `is_signed`,
`signature_status`.

## signature_status and is_signed

Map the vendor signing status word to `XDM_CONST.SIGNATURE_STATUS_*` (see
[xdm-const.md](xdm-const.md)): Valid -> `SIGNED_VERIFIED`;
Expired / Revoked / mismatched -> `SIGNED_INVALID`; an explicitly unsigned image
-> `UNSIGNED`; Unavailable / anything else -> `STATUS_UNKNOWN`. Set the
`is_signed` boolean companion when the log provides it.

## integrity_level (Number, not a constant)

`xdm.*.process.integrity_level` is typed Number. Map the Windows integrity word
to an integer -- do NOT emit an `XDM_CONST.INTEGRITY_LEVEL_*` token:

```
tmp_il = lowercase(to_string(tmp_integrity_word)),
xdm.source.process.integrity_level = if(
    tmp_il contains "untrusted", 0,
    tmp_il contains "low", 1,
    tmp_il contains "medium", 2,
    tmp_il contains "high", 3,
    tmp_il contains "system", 4)
```

## Deriving common endpoint fields (recipes)

Hashes from a Sysmon `Hashes` blob (`MD5=...,SHA256=...`), which is one field:

```
xdm.source.process.executable.sha256 = arrayindex(
    regextract(to_string(tmp_hashes), "SHA256=([0-9A-Fa-f]{64})"), 0),
xdm.source.process.executable.md5 = arrayindex(
    regextract(to_string(tmp_hashes), "MD5=([0-9A-Fa-f]{32})"), 0)
```

`DOMAIN\user` split (guard the `-` / null empty markers first):

```
xdm.source.user.username = arrayindex(
    regextract(to_string(tmp_user), "\\\\([^\\\\]+)$"), 0),
xdm.source.user.domain = arrayindex(
    regextract(to_string(tmp_user), "^([^\\\\]+)\\\\"), 0)
```

Process name from an image path (works for Windows `\` and Linux `/`):

```
xdm.source.process.name = arrayindex(
    regextract(to_string(tmp_image), "([^\\\\/]+)$"), 0)
```

Single-field IPv4 vs IPv6 split (Sysmon 3 `SourceIp` / `DestinationIp`):

```
xdm.source.ipv4 = if(to_string(tmp_ip) ~= ":", null, tmp_ip),
xdm.source.ipv6 = if(to_string(tmp_ip) ~= ":", tmp_ip, null)
```

Numbers vs strings: `pid` is a Number (`to_integer(to_number(...))`);
`parent_id` is a String.

## Linux commands

- auditd `EXECVE`: reconstruct the command from the `a0 a1 a2 ...` argv fields
  (or the `proctitle`), map it to `xdm.source.process.command_line`, `exe=` to
  `xdm.source.process.executable.path`, `pid=` to `xdm.source.process.pid`, and
  the `auid` / `uid` to `xdm.source.user.username`. A `SYSCALL execve` is a
  process creation (`OPERATION_TYPE_PROCESS_CREATE`); a bare command is
  `OPERATION_TYPE_EXECUTION`.
- `sudo` / shell / PAM: a `USER=root ; COMMAND=/bin/sh` line -- the command being
  run goes to `xdm.target.process.command_line`, the invoking user to
  `xdm.source.user.username`, operation `OPERATION_TYPE_EXECUTION`.
- Linux endpoint logs usually arrive over syslog, so the syslog envelope HARD
  RULE applies: parse the envelope relay-aware and anchor every payload field on
  its own token (see [syslog-envelope.md](syslog-envelope.md)).

## AAA / network-device command accounting

A TACACS+ / RADIUS / network-device feed carries authentication, authorization,
and accounting records. They do NOT all belong to the authentication story --
discriminate by record kind:

- authentication (AUTHEN, a login attempt) -> the authentication story.
- authorization (AUTHOR, a permit / deny decision) -> authentication story; the
  outcome carries the decision.
- accounting with a command (`cmd=`, `CmdSet`, `Command=`) -> a COMMAND
  EXECUTION event, not authentication. Set `xdm.event.type` to the source label,
  map the executed command to `xdm.target.process.command_line`, keep operation
  `XDM_CONST.OPERATION_TYPE_AUDIT` (an audit trail of what was run) with no
  outcome, put the operator on `xdm.source.user.*` and the administered device on
  `xdm.target.*`, and do NOT tag it `EVENT_TAG_AUTHENTICATION`.
- accounting with no command (a session Start / Stop) -> a session-audit record:
  operation `OPERATION_TYPE_AUDIT`, no outcome, and `elapsed_time` ->
  `xdm.event.duration` (seconds to milliseconds, see
  [authentication-mapping.md](authentication-mapping.md)).

See [authentication-mapping.md](authentication-mapping.md) (AAA gateways).

## Worked shape (Sysmon process creation, EventID 1)

The running program is the source process; map the image to a leaf (never the
`executable` parent, which is a Number), set the precise operation verb, and
put the channel in `event.type` with the semantic name in `original_event_type`.

```
[MODEL: dataset=microsoft_sysmon_raw]
filter
    _raw_log != null
| alter
    tmp_channel = json_extract_scalar(_raw_log, "$.channel"),
    tmp_eid = json_extract_scalar(_raw_log, "$.event_id"),
    tmp_image = json_extract_scalar(_raw_log, "$.event_data.Image"),
    tmp_cmd = json_extract_scalar(_raw_log, "$.event_data.CommandLine"),
    tmp_pid = json_extract_scalar(_raw_log, "$.event_data.ProcessId"),
    tmp_user = json_extract_scalar(_raw_log, "$.event_data.User"),
    tmp_hashes = json_extract_scalar(_raw_log, "$.event_data.Hashes")
| alter
    xdm.event.type = tmp_channel,
    xdm.event.id = to_string(tmp_eid),
    xdm.event.original_event_type = "Process Create",
    xdm.event.operation = XDM_CONST.OPERATION_TYPE_PROCESS_CREATE,
    xdm.source.host.os_family = XDM_CONST.OS_FAMILY_WINDOWS,
    xdm.source.process.executable.path = tmp_image,
    xdm.source.process.name = arrayindex(regextract(to_string(tmp_image), "([^\\\\/]+)$"), 0),
    xdm.source.process.command_line = tmp_cmd,
    xdm.source.process.pid = to_integer(to_number(tmp_pid)),
    xdm.source.process.executable.sha256 = arrayindex(regextract(to_string(tmp_hashes), "SHA256=([0-9A-Fa-f]{64})"), 0),
    xdm.source.user.username = arrayindex(regextract(to_string(tmp_user), "\\\\([^\\\\]+)$"), 0),
    xdm.source.user.domain = arrayindex(regextract(to_string(tmp_user), "^([^\\\\]+)\\\\"), 0),
    xdm.event.description = concat("process ", to_string(tmp_cmd))
;
```
