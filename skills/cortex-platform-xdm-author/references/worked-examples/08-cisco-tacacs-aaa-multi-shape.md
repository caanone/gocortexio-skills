<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Walkthrough 8 -- Cisco TACACS+ AAA, nine event shapes through one rule

Vendor / product: Cisco / Secure ACS TACACS+ (the same structure applies
to any tac_plus-style daemon, and the guidance generalises to RADIUS and
Cisco ISE syslog -- see the Cisco ISE syslog reference for the full ISE
message catalogue). Dataset: `cisco_tacacs_raw`, RFC 3164 syslog.

What this walkthrough shows: an AAA gateway emits MANY event shapes from
one daemon family -- structured key=value, legacy freeform prose, and
pure diagnostic chatter -- and one MODEL rule normalises all of them
through a single shared assignment stage while classifying PER RECORD.
It applies the AAA topology and vocabulary rules from
[authentication-mapping.md](../authentication-mapping.md) (AAA gateways
section), the Stage 0 envelope from
[syslog-envelope.md](../syslog-envelope.md), the full 14-field
authentication mandatory set, and the record-level classification and
catch-all from
[record-classification.md](../record-classification.md). Not every
record is authentication: the login, authorization and session shapes
carry `EVENT_TAG_AUTHENTICATION` (no network tag -- these hold no
transport flow), a command-accounting record is a PROCESS event with no
tag, and any line the rule cannot classify gets the catch-all so the
datamodel row count still equals the raw count.

## The shape census

One day of records from this daemon family falls into nine groups:

| # | Shape | Discriminator | Treatment |
| --- | --- | --- | --- |
| 1 | AUTH PERMIT (structured kv) | `type=AUTHENTICATION action=PERMIT` | login success |
| 2 | AUTH DENY (structured kv) | `type=AUTHENTICATION action=DENY` | login failure + reason |
| 3 | Command accounting | `type=ACCOUNTING action=Stop` with `cmd=` | PROCESS event; `cmd` -> `target.process.command_line`; no auth tag |
| 4 | Session accounting Start | `type=ACCOUNTING action=Start` | auth story; session lifecycle, NO outcome |
| 5 | Session accounting Stop | `type=ACCOUNTING action=Stop`, no `cmd=` | auth story; duration from elapsed_time |
| 6 | Legacy authorization permitted | `Authorization permitted for` | auth story; audit success |
| 7 | Legacy authorization denied | `Authorization denied for` | auth story; audit failure |
| 8 | Legacy login | `Logged in Successfully` / `Login Failure` | login success / failure |
| 9 | Diagnostic chatter | parser hooks, key errors | CATCH-ALL: `original_event_type = "GOCORTEX_UNMODELLED"`, blank tags |

Two structural decisions follow:

- Never drop a record. The only filter is `_raw_log != null`; there is
  no discriminator filter. Every record produces a row, so a
  `datamodel` search returns the same count as the raw dataset. The
  classification `if()`-chains recognise each shape by its own
  discriminator and let the diagnostic chatter fall through to the
  catch-all (`xdm.event.original_event_type = "GOCORTEX_UNMODELLED"`,
  blank tags) rather than being discarded.
- One pipeline, shared drain. The shape families converge on the same
  identities (`coalesce()` over the per-shape temps) and the same
  assignment stage, so nothing drifts between duplicated drains. The
  alternative -- one `;`-terminated pipeline per family inside the one
  MODEL block -- is equally valid and better when the shapes share
  little; here they share almost everything.

## The AAA topology

Three parties, not two. The principal (`user=`) is the source; the
principal's workstation (`src_ip=`) is the source address; the network
device being accessed (`dvc_ip=` / `at <ip>`) is the target; and the
AAA server that validates the request is the observer (its name comes
from the Stage 0 envelope host). `xdm.auth.service = "TACACS+"` is the
authentication service name -- the AAA protocol itself (it is the
service NAME, not an "SP"/"IDP" role; those values do not exist in XDM).

TACACS+ principals (`svc_nms1`, `alice.admin`) are not UPN-shaped,
but `xdm.source.user.upn` is the mandatory correlation key and cannot
be empty: map the raw principal to it anyway, mirrored into
`xdm.source.user.username`.

## The full rule

```
[MODEL: dataset = cisco_tacacs_raw]
filter
    _raw_log != null
| alter
    _pri        = to_integer(to_number(arrayindex(regextract(_raw_log, "^<(\d{1,3})>"), 0))),
    _host_5424  = arrayindex(regextract(_raw_log, "^<\d{1,3}>\d+\s+\S+\s+(\S+)\s"), 0),
    _host_3164  = arrayindex(regextract(_raw_log, "^<\d{1,3}>[A-Za-z]{3}\s+\d+\s+[\d:]+\s+(\S+)\s"), 0)
| alter
    _syslog_host_raw = coalesce(_host_5424, _host_3164)
| alter
    _syslog_host = if(_syslog_host_raw != "-", _syslog_host_raw)
| alter
    _pri_facility = to_integer(divide(_pri, 8))
| alter
    _pri_severity = to_integer(subtract(_pri, multiply(_pri_facility, 8)))
| alter
    _pri_log_level = if(
        _pri_severity <= 2, XDM_CONST.LOG_LEVEL_CRITICAL,
        _pri_severity = 3,  XDM_CONST.LOG_LEVEL_ERROR,
        _pri_severity = 4,  XDM_CONST.LOG_LEVEL_WARNING,
        _pri_severity = 5,  XDM_CONST.LOG_LEVEL_NOTICE,
        _pri_severity != null, XDM_CONST.LOG_LEVEL_INFORMATIONAL)
| alter
    _kv_type = arrayindex(regextract(_raw_log, "type=(\w+)"), 0),
    _kv_action = arrayindex(regextract(_raw_log, "action=(\w+)"), 0),
    _kv_user = arrayindex(regextract(_raw_log, "user=\"([^\"]+)\""), 0),
    _kv_dvc_ip = arrayindex(regextract(_raw_log, "dvc_ip=([\d.]+)"), 0),
    _kv_src_ip = arrayindex(regextract(_raw_log, "src_ip=([\d.]+)"), 0),
    _kv_reason = arrayindex(regextract(_raw_log, "reason=\"([^\"]+)\""), 0),
    _kv_rule = arrayindex(regextract(_raw_log, "rule=\"([^\"]+)\""), 0),
    _kv_task = arrayindex(regextract(_raw_log, "task_id=(\d+)"), 0),
    _kv_priv = arrayindex(regextract(_raw_log, "priv_lvl=(\d+)"), 0),
    _kv_cmd = arrayindex(regextract(_raw_log, "cmd=\"([^\"]+)\""), 0),
    _kv_elapsed = arrayindex(regextract(_raw_log, "elapsed_time=(\d+)"), 0),
    _az_result = arrayindex(regextract(_raw_log, "Authorization (permitted|denied) for"), 0),
    _az_user = arrayindex(regextract(_raw_log, "Authorization (?:permitted|denied) for ([A-Za-z0-9._-]+)"), 0),
    _az_ip = arrayindex(regextract(_raw_log, "Authorization (?:permitted|denied) for \S+ at ([\d.]+)"), 0),
    _az_group = arrayindex(regextract(_raw_log, "group ([^,.]+)"), 0),
    _lg_result = arrayindex(regextract(_raw_log, "(Logged in Successfully|Login Failure)"), 0),
    _lg_user = arrayindex(regextract(_raw_log, "user=(.+?) from "), 0),
    _lg_from_ip = arrayindex(regextract(_raw_log, "from ([\d.]+) to "), 0),
    _lg_to_ip = arrayindex(regextract(_raw_log, " to ([\d.]+)"), 0)
| alter
    _user = coalesce(_kv_user, _az_user, _lg_user),
    _src_ip = coalesce(_kv_src_ip, _lg_from_ip),
    _dvc_ip = coalesce(_kv_dvc_ip, _az_ip, _lg_to_ip),
    _outcome_token = coalesce(_kv_action, _az_result, _lg_result),
    _oet_kv = if(_kv_type != null, concat(_kv_type, " ", _kv_action)),
    _oet_az = if(_az_result != null, concat("Authorization ", _az_result))
| alter
    _oet = coalesce(_oet_kv, _oet_az, _lg_result)
| alter
    xdm.observer.vendor = "Cisco",
    xdm.observer.product = "Secure ACS TACACS+",
    xdm.observer.name = _syslog_host,
    xdm.event.log_level = _pri_log_level,
    xdm.event.type = if(
        _kv_cmd != null, "process",
        _oet != null, "authentication",
        "GOCORTEX_UNMODELLED"),
    xdm.event.tags = if(
        _kv_cmd != null, null,
        _oet != null, arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),
        null),
    xdm.event.original_event_type = coalesce(_oet, "GOCORTEX_UNMODELLED"),
    xdm.event.operation = if(
        _kv_type = "ACCOUNTING", XDM_CONST.OPERATION_TYPE_AUDIT,
        _az_result != null, XDM_CONST.OPERATION_TYPE_AUDIT,
        _oet != null, XDM_CONST.OPERATION_TYPE_AUTH_LOGIN),
    xdm.event.operation_sub_type = if(
        _kv_type = "AUTHENTICATION", "password",
        _lg_result != null, "password"),
    xdm.target.process.command_line = _kv_cmd,
    xdm.event.outcome = if(
        _outcome_token = "PERMIT", XDM_CONST.OUTCOME_SUCCESS,
        _outcome_token = "permitted", XDM_CONST.OUTCOME_SUCCESS,
        _outcome_token = "Logged in Successfully", XDM_CONST.OUTCOME_SUCCESS,
        _outcome_token = "DENY", XDM_CONST.OUTCOME_FAILED,
        _outcome_token = "denied", XDM_CONST.OUTCOME_FAILED,
        _outcome_token = "Login Failure", XDM_CONST.OUTCOME_FAILED),
    xdm.event.outcome_reason = if(
        _kv_reason = "Bad Password", "bad_credentials",
        _kv_reason = "No such user", "user_does_not_exist",
        _kv_reason != null, _kv_reason),
    xdm.event.duration = to_integer(multiply(to_number(_kv_elapsed), 1000)),
    xdm.event.description = concat("TACACS+ ", _oet, " for ", _user),
    xdm.auth.service = "TACACS+",
    xdm.auth.privilege_level = if(
        _kv_priv = "15", XDM_CONST.PRIVILEGE_LEVEL_ADMIN,
        _kv_priv != null, XDM_CONST.PRIVILEGE_LEVEL_USER),
    xdm.source.user.upn = if(
        _user contains "@", _user,
        _user != null, concat(_user, "@localhost")),
    xdm.source.user.identity_type = if(
        _user != null, XDM_CONST.IDENTITY_TYPE_USER,
        XDM_CONST.IDENTITY_TYPE_UNKNOWN),
    xdm.source.user.user_type = if(
        _user = null, XDM_CONST.USER_TYPE_REGULAR,
        _user contains "$", XDM_CONST.USER_TYPE_MACHINE_ACCOUNT,
        lowercase(_user) ~= "^svc[-_.]|service|gserviceaccount",
            XDM_CONST.USER_TYPE_SERVICE_ACCOUNT,
        XDM_CONST.USER_TYPE_REGULAR),
    xdm.source.user.username = _user,
    xdm.source.user.groups = if(_az_group != null, arraycreate(_az_group), null),
    xdm.source.ipv4 = _src_ip,
    xdm.source.port = to_integer(0),
    xdm.target.ipv4 = coalesce(_dvc_ip, ""),
    xdm.target.port = to_integer(0),
    xdm.network.ip_protocol = XDM_CONST.IP_PROTOCOL_TCP,
    xdm.network.session_id = _kv_task,
    xdm.network.rule = _kv_rule
;
// REVIEW UNMODELLED -- list records this rule could not classify and
// grow it to cover them:
//   datamodel dataset = cisco_tacacs_raw
//   | filter xdm.event.original_event_type = "GOCORTEX_UNMODELLED"
//   | fields xdm.event.original_event_type, cisco_tacacs_raw._raw_log
//
// RAISE SKILL ISSUES -- report a mis-mapping (include the REVIEW
// UNMODELLED output above): https://github.com/gocortexio/skills/issues
```

## Key decisions worth copying

- Classify per record, never drop. The `xdm.event.type` / `xdm.event.tags`
  if-chains recognise each shape by its own discriminator: a
  command-accounting record (`_kv_cmd` present) is a PROCESS event with no
  tag, the login / authorization / session shapes (`_oet` present) are the
  authentication story, and everything else -- the Inconsistent-lengths /
  PostSearchHook / createreturnattrs chatter -- falls through to the
  catch-all (`xdm.event.original_event_type = "GOCORTEX_UNMODELLED"`, blank
  tags). Nothing is filtered out, so the datamodel row count matches raw.
- Command accounting is a command execution, not authentication: the
  executed `cmd=` goes to `xdm.target.process.command_line` with
  `xdm.event.type = "process"`, `operation OPERATION_TYPE_AUDIT` and no
  outcome, and NO `EVENT_TAG_AUTHENTICATION`.
- Outcome only on conclusive events. PERMIT / permitted / Logged in
  Successfully -> `OUTCOME_SUCCESS`; DENY / denied / Login Failure ->
  `OUTCOME_FAILED`; accounting Start / Stop is session lifecycle and
  the if-chain deliberately has no default, so outcome stays null there.
- `xdm.event.operation` splits AUTH_LOGIN (authentication + legacy
  login) from AUDIT (command / session accounting + authorization). The
  auth method is `"password"` on the login shapes; the final AUTH_LOGIN
  branch is gated on `_oet != null` so unrecognised chatter gets no
  operation.
- Reason normalisation with passthrough: `Bad Password` ->
  `bad_credentials`, `No such user` -> `user_does_not_exist`, and
  any unrecognised vendor reason passes through unchanged rather than
  being forced to a placeholder.
- The async guard: every address capture is `([\d.]+)`, so the legacy
  placeholder token `from async` can never land in an IPv4 field -- it
  simply fails the capture and the temp stays null.
- Bounded username capture: `user=(.+?) from ` survives principals
  with embedded spaces (`user1 line1.co`); the structured shapes use
  the quoted capture instead.
- The upn is ALWAYS UPN-shaped: a bare principal gets
  `concat(_user, "@localhost")`, and an identity that already
  carries `@` passes through unchanged. The raw principal stays in
  `xdm.source.user.username`.
- `priv_lvl` maps to the closed list: `15` ->
  `PRIVILEGE_LEVEL_ADMIN`, anything else present ->
  `PRIVILEGE_LEVEL_USER`. `group` becomes a one-element
  `xdm.source.user.groups` array.
- `task_id` -> `xdm.network.session_id` correlates the Start / Stop /
  command records of one shell session; `elapsed_time` is SECONDS and
  `xdm.event.duration` is MILLISECONDS, so the mapping multiplies by
  1000 (function-form, ERR-012 safe).

## NOT MAPPED, with reasons

```
NOT MAPPED
  port=            -- TTY / line name (vty0, /dev/pts/7, rest_http), not a TCP
                      port; the mandatory integer ports take to_integer(0)
  client=          -- policy network-match classifier (CIDR), not an endpoint
  timezone=        -- session-local display detail
  start_time= / stop_time= -- Cortex sets _time at INGEST (WARN-018);
                      duration already carries elapsed_time
  disc_cause= / disc_cause-ext= -- vendor disconnect taxonomy with no XDM
                      home; retain in the raw record
  service=         -- TACACS service selector (shell / ppp); not an
                      application protocol observation
```

## Checklist

```
[ ] only filter is _raw_log != null (no discriminator filter; nothing dropped)
[ ] type/tags classified per record; chatter -> GOCORTEX_UNMODELLED catch-all
[ ] command accounting -> event.type "process", cmd -> target.process.command_line, no auth tag
[ ] REVIEW UNMODELLED query present with the real dataset
[ ] Stage 0 envelope: PRI-anchored host + priority decode (WARN-040/041)
[ ] all 14 authentication mandatory fields mapped or padded (WARN-042)
[ ] auth shapes carry EVENT_TAG_AUTHENTICATION only -- no network tag without a transport flow
[ ] outcome null on accounting lifecycle rows; SUCCESS / FAILED elsewhere
[ ] upn ALWAYS UPN-shaped: contains-@ passthrough, else concat(_user, "@localhost")
[ ] address captures restricted to [\d.]+ (the async guard)
[ ] proven with verify_rule.py across one line from every shape group
```
