<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Process and command-execution mapping

Process and command-execution events describe a program running or a
command being issued: an endpoint process start/stop, an EDR
process-creation event, a script run, a database statement, a remotely
executed command, or an AAA / network-device command-accounting record
(a TACACS+ `cmd=` line). These map to the `xdm.*.process.*` field
family. A command-accounting record is a command execution, not an
authentication event: `xdm.event.type` is a process value, the command
goes to `xdm.target.process.command_line`, operation is
`OPERATION_TYPE_AUDIT`, and there is no outcome; see the AAA section
below and [authentication-mapping.md](authentication-mapping.md).

This is a RECOMMENDED mapping set, not a mandatory story. XDM has only
two story tags (`XDM_CONST.EVENT_TAG_AUTHENTICATION`,
`XDM_CONST.EVENT_TAG_NETWORK`) and there is no process tag, so there is
no mandatory-field gate here -- the linter raises the advisory WARN-044
to suggest the companion fields, never to block. Map what the log
provides.

## Actor vs target

- The process that ACTED (the running program, the session issuing the
  command) is the source: `xdm.source.process.*`.
- The process being ACTED UPON (a child that was terminated, a target
  binary) is the target: `xdm.target.process.*`.
- For a local endpoint / EDR process, the command the process ran is
  `xdm.source.process.command_line`. Use `xdm.target.process.command_line`
  for a process the event acts upon (a child that was launched or
  terminated).

## Recommended fields (map when present)

| XDM target | Notes |
| --- | --- |
| `xdm.source.process.name` | Short process/image name (`sshd`, `powershell.exe`). |
| `xdm.source.process.pid` | Process id. Number: `to_integer(...)`. |
| `xdm.source.process.command_line` | Full command line the process ran. |
| `xdm.source.process.executable.path` | Full path to the image on disk. |
| `xdm.source.process.executable.filename` | Image filename only. |
| `xdm.source.process.executable.directory` | Directory of the image. |
| `xdm.source.process.executable.md5` | Image MD5 hash. |
| `xdm.source.process.executable.sha256` | Image SHA-256 hash. |
| `xdm.source.process.executable.signer` | Code-signing signer. |
| `xdm.source.process.parent_id` | Parent process id (String). |
| `xdm.target.process.command_line` | Command line of the target process (the process acted upon). |
| `xdm.target.process.name` | Target process/image name. |
| `xdm.target.process.pid` | Target process id. Number. |

The target family mirrors the source family; use `xdm.target.process.*`
for the process acted upon.

Guardrail: never assign a value to `xdm.source.process.executable` (or
`xdm.target.process.executable`) directly -- that path is typed Number
in the schema, a parent node, not the image name. Map the leaves
(`executable.path`, `executable.filename`, ...) instead.

## Deriving the fields

The command / image usually arrives under one of these vendor names
(from the anchor dictionary): `command_line`, `commandLine`,
`ProcessCommandLine`, `InitiatingProcessCommandLine`, `processCmd`,
`args`, `cmd`, `sql_command` for the command line; `process`,
`process_name`, `image`, `proc` for the name; `pid`, `process_id`,
`ProcessId` for the pid; `image_path`, `path`, `exe` for the executable
path.

Numeric fields (`pid`, `parent_id` is a String) follow the usual
coercion: `xdm.source.process.pid = to_integer(to_number(tmp_pid))`.

## AAA / network-device command accounting

A TACACS+ / RADIUS / network-device feed carries authentication,
authorization, and accounting records. They do NOT all belong to the
authentication story -- discriminate by record kind:

- authentication (AUTHEN, a login attempt) -> the authentication story.
- authorization (AUTHOR, a permit/deny decision on a request) ->
  authentication story; the outcome carries the decision.
- accounting with a command (`cmd=`, `CmdSet`, `Command=`) -> a COMMAND
  EXECUTION event, not authentication. Set `xdm.event.type` to a process
  value (must NOT contain "authentication"), map the executed command to
  `xdm.target.process.command_line`, keep operation
  `XDM_CONST.OPERATION_TYPE_AUDIT` with no outcome, put the operator on
  `xdm.source.user.*` and the administered device on `xdm.target.*`, and
  do NOT tag it `EVENT_TAG_AUTHENTICATION`.
- accounting with no command (a session Start/Stop) -> a session-audit
  record: operation `OPERATION_TYPE_AUDIT`, no outcome, and
  `elapsed_time` -> `xdm.event.duration` (seconds to milliseconds, see
  [authentication-mapping.md](authentication-mapping.md)).

See [authentication-mapping.md](authentication-mapping.md) (AAA
gateways). A command-accounting record IS a command execution -- the log
records what was run on the device -- so it belongs to this family, not
the authentication story.

## xdm.event.operation for a command execution

`xdm.event.operation` is a closed `XDM_CONST.OPERATION_TYPE_*` enum. The
confirmed members do not include a generic "command execution" value, so
DO NOT invent one. Derive only a member that genuinely applies:
`XDM_CONST.OPERATION_TYPE_CONFIG_CHANGE` for a configuration command,
`XDM_CONST.OPERATION_TYPE_CREATE` / `OPERATION_TYPE_UPDATE` /
`OPERATION_TYPE_DELETE` for a clear create/modify/remove. When the record
is a plain command execution with no matching member, leave
`xdm.event.operation` unmapped -- the executed command itself is fully
captured in `command_line`. Never assert an operation the closed list
does not contain (see [authentication-mapping.md](authentication-mapping.md)
"Deriving xdm.event.operation"). AAA command accounting is the one case
with a definite member: it is an audit trail of what was run, so use
`XDM_CONST.OPERATION_TYPE_AUDIT`.

## Worked shape (endpoint process creation)

An endpoint / EDR process-creation record. The running program is the
source process; map the image to a leaf (never the `executable` parent,
which is a Number), and leave `xdm.event.operation` unmapped when no
closed-list member fits.

```
[MODEL: dataset=vendor_edr_raw]
filter
    _raw_log != null
| alter
    tmp_user = json_extract_scalar(_raw_log, "$.user"),
    tmp_img = json_extract_scalar(_raw_log, "$.image"),
    tmp_cmd = json_extract_scalar(_raw_log, "$.command_line"),
    tmp_pid = json_extract_scalar(_raw_log, "$.pid")
| alter
    xdm.event.type = "process creation",
    xdm.source.user.username = tmp_user,
    xdm.source.process.executable.path = tmp_img,
    xdm.source.process.command_line = tmp_cmd,
    xdm.source.process.pid = to_integer(to_number(tmp_pid)),
    xdm.event.description = concat("process ", tmp_cmd, " by ", tmp_user)
;
```
