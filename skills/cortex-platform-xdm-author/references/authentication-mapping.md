<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Authentication-event mandatory mapping

Authentication events feed the XDM authentication story and identity
analytics. The story is only created automatically when a fixed set of
XDM fields is mapped. A mandatory field left unmapped drops the event
from the story and from identity analytics, so this reference is the
authoritative checklist for any rule that models a login, logon, MFA,
SSO, or other credential-validation event.

This guidance is host-agnostic and format-agnostic. Extraction differs
per source format (syslog RFC 3164 / RFC 5424, JSON, JSONL, CEF, LEEF,
key=value), but the XDM target fields and their requirement level are
identical in every case. Map them in the MODEL rule after extraction.

## When this applies (auto-detection)

Treat a sample as an authentication event whenever its field names or
values carry a login / logon / sign-in / MFA / SSO / credential signal,
regardless of vendor. Common signals:

- Field names containing `login`, `logon`, `signin`, `auth`, `authn`,
  `mfa`, `2fa`, `otp`, `sso`, `saml`, `oauth`, `kerberos`, `ntlm`,
  `credential`, `password`, `upn`, `idp`.
- Event-type or action values such as `user.authentication.sso`,
  `microsoft.login.success`, `LOGIN_FAILED`, `logged in`, `mfa challenge`.

`scripts/profile_log.py` reports this signal in an `authentication`
block of the worksheet so the detection is deterministic rather than a
judgement call. When detected, apply the mandatory set below.

When detected, `scripts/scaffold_rule.py` pre-populates the mandatory
set: it pads the fields that have an official placeholder (tags,
operation, service, ip_protocol, the transport ports, target.ipv4),
sets `xdm.event.type` to `authentication`, and lists the fields that
must come from the raw log (`xdm.source.user.upn`, `xdm.source.ipv4`,
`xdm.event.original_event_type`, `xdm.event.outcome`) as TODOs rather
than padding them with a static value the platform would reject.

Enforcement is advisory. `scripts/lint_rule.py` classifies a MODEL rule
as authentication either from an explicit XDM marker (the
`EVENT_TAG_AUTHENTICATION` tag, an `OPERATION_TYPE_AUTH_*` operation, or
`authentication` in `xdm.event.type`) or from a broader auth literal
(`login`, `logon`, `signin`, `mfa`, `sso`, ...) in an event-classification
field such as `xdm.event.original_event_type = "user.login"`, so a rule
that models authentication without ever using an explicit marker is still
caught. It raises WARN-042 (warning
severity, never an error) for each mandatory field that an auto-detected
authentication rule leaves unmapped, and also for each mapped mandatory
field whose value violates the closed vocabulary the story demands (the
wrong const, a static source address, or a list where a string is
required). Value conformance is conservative: only a definitively wrong,
self-contained literal is flagged, so a value resolved from a temp, an
xdm read, or a const expression is never second-guessed. The linter never
blocks on this and the exit code stays 0. The author decides; the warning
is a reminder.

## Mandatory fields (all 12 must be mapped)

| XDM target | Type | Notes |
| --- | --- | --- |
| `xdm.source.ipv4` | string | External source IP the IdP / SaaS observed. Map from the raw field that best represents the real client (prefer pre-proxy `client_ip` / `source_ip` / `original_client_ip`). Never static, empty, or a list. |
| `xdm.source.port` | integer | Map the real value; otherwise `to_integer(0)`. |
| `xdm.target.ipv4` | string | Map a real value if present; otherwise the empty string `""`. Do not map a list. |
| `xdm.target.port` | integer | Map the real value; otherwise `to_integer(0)`. |
| `xdm.network.ip_protocol` | integer (enum) | Assign the appropriate `XDM_CONST.IP_PROTOCOL_*` (interactive auth over TCP -> `IP_PROTOCOL_TCP`). |
| `xdm.event.type` | string | Resolve to a value that contains `authentication`. |
| `xdm.event.tags` | array | `arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION)`. |
| `xdm.event.operation` | string (enum) | `XDM_CONST.OPERATION_TYPE_AUTH_LOGIN` (password only) or `XDM_CONST.OPERATION_TYPE_AUTH_MFA` (involves MFA). |
| `xdm.event.original_event_type` | string | The raw vendor event name exactly as logged (e.g. `user.authentication.sso`, `microsoft.login.success`). |
| `xdm.event.outcome` | string (enum) | Only `XDM_CONST.OUTCOME_SUCCESS` or `XDM_CONST.OUTCOME_FAILED`, and only on conclusive events. Do not set on intermediate steps. |
| `xdm.auth.service` | string | Role in the flow: `"SP"` (service provider, initiates) or `"IDP"` (identity provider, validates). The same system can be IDP in one event and SP in another, so map per event type. |
| `xdm.source.user.upn` | string | The authenticated identity in UPN format (`jane.doe@company.com`). Cannot be empty. This is the central correlation key across IdPs -- it is `upn`, not `username`. |

Placeholder policy for the mandatory set:

- Integer fields with no source value -> `to_integer(0)` (`xdm.source.port`,
  `xdm.target.port`).
- `xdm.target.ipv4` is a string here -> a real value, or the empty
  string `""`. Never a list.
- `xdm.source.ipv4` must always come from the raw log -- never a static
  string, list, or empty string.
- `xdm.event.outcome` resolves to `XDM_CONST.OUTCOME_SUCCESS` or
  `XDM_CONST.OUTCOME_FAILED` only.
- The event time (generated time) is mapped automatically; do not set it
  manually.

Note on identity: `xdm.source.user.upn` is the mandatory key. The
human-readable display name is the optional `xdm.source.user.username`
below -- do not substitute one for the other.

## Worked shape (JSON source)

A complete MODEL rule that maps all 12 mandatory fields. The extraction
stage changes per format; the assignment stage does not.

```
[MODEL: dataset=vendor_idp_raw]
filter
    _raw_log != null
| alter
    _event = json_extract_scalar(_raw_log, "$.eventType"),
    _upn = json_extract_scalar(_raw_log, "$.actor.alternateId"),
    _src_ip = json_extract_scalar(_raw_log, "$.client.ipAddress"),
    _src_port = json_extract_scalar(_raw_log, "$.client.port"),
    _result = json_extract_scalar(_raw_log, "$.outcome.result"),
    _factor = json_extract_scalar(_raw_log, "$.authenticationContext.method")
| alter
    xdm.event.type = if(_event != null, "authentication", ""),
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),
    xdm.event.original_event_type = _event,
    xdm.event.operation = if(
        _factor != null, XDM_CONST.OPERATION_TYPE_AUTH_MFA,
        _event != null, XDM_CONST.OPERATION_TYPE_AUTH_LOGIN),
    xdm.event.outcome = if(
        _result ~= "[Ss]uccess", XDM_CONST.OUTCOME_SUCCESS,
        _result != null, XDM_CONST.OUTCOME_FAILED),
    xdm.auth.service = "IDP",
    xdm.source.user.upn = _upn,
    xdm.source.ipv4 = _src_ip,
    xdm.source.port = to_integer(to_number(_src_port)),
    xdm.target.ipv4 = "",
    xdm.target.port = to_integer(0),
    xdm.network.ip_protocol = XDM_CONST.IP_PROTOCOL_TCP
;
```

## Optional fields (map when the source provides them)

These enrich the story but are not required for it to be created. Map
them when present; omit them otherwise.

| XDM target | Notes |
| --- | --- |
| `xdm.event.outcome_reason` | Normalise provider error strings into one supported reason value (`user_does_not_exist`, `bad_credentials`, `account_locked`, `mfa_failure`, and similar). |
| `xdm.event.description` | Deterministic `concat()` summary; see [transformation-patterns.md](transformation-patterns.md). |
| `xdm.event.operation_sub_type` | The auth method (`password`, `sms`, `voice`, `application`, and similar). Distinct from the mandatory `xdm.event.operation`. |
| `xdm.source.user.identifier` | Persistent canonical id (GUID / SID). |
| `xdm.source.user.username` | Human-readable display name. NOT the identity key. |
| `xdm.source.user.user_type` | `XDM_CONST.USER_TYPE_REGULAR` / `USER_TYPE_SERVICE_ACCOUNT` / `USER_TYPE_MACHINE_ACCOUNT`. |
| `xdm.source.user_agent` | Full user-agent string of the client. |
| `xdm.auth.privilege_level` | `XDM_CONST.PRIVILEGE_LEVEL_GUEST` / `PRIVILEGE_LEVEL_USER` / `PRIVILEGE_LEVEL_ADMIN` / `PRIVILEGE_LEVEL_SYSTEM`. |
| `xdm.logon.type` | `XDM_CONST.LOGON_TYPE_INTERACTIVE` / `LOGON_TYPE_SERVICE`. |
| `xdm.source.host.device_id` | Stable per-device id; fall back to source IP when absent. |
| `xdm.source.host.hostname` | Device name. |
| `xdm.source.host.device_category` | Client class (`Computer`, `Mobile`, `Tablet`, `IOT`). |
| `xdm.source.host.os_family` | `XDM_CONST.OS_FAMILY_WINDOWS` / `OS_FAMILY_MACOS` / `OS_FAMILY_LINUX`. For a mobile OS with no listed constant, omit the constant and keep the raw string in `xdm.source.host.os`. |
| `xdm.source.host.os` | Raw OS string. |
| `xdm.source.application.name` | Browser vendor. |
| `xdm.source.application.version` | Browser version. |
| `xdm.target.resource.id` | Accessed resource / app id. |
| `xdm.target.resource.name` | Readable accessed resource / app name. |
| `xdm.source.location.city` | Geo of the source. The companion geo leaves are `xdm.source.location.country`, `xdm.source.location.region`, `xdm.source.location.continent`, `xdm.source.location.timezone`, `xdm.source.location.latitude`, `xdm.source.location.longitude`. |
| `xdm.network.session_id` | Aggregates multiple actions across a session window. |
| `xdm.session_context_id` | Correlates the events of a single auth request / transaction (narrower than `xdm.network.session_id`). |

Constants used above live in [xdm-const.md](xdm-const.md); every target
path is defined in [xdm-schema.md](xdm-schema.md).
