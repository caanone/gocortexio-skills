<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Walkthrough 6 -- Okta authentication, one event in two formats

Vendor / product: Okta / Identity Cloud. Datasets: `okta_systemlog_json_raw` (System Log API, native JSON) and `okta_systemlog_syslog_raw` (same events relayed through a SIEM syslog connector).

What this walkthrough shows: the authentication story is created only when the full mandatory field set from [authentication-mapping.md](../authentication-mapping.md) is mapped, and that mapping is identical no matter which wire format the event arrives in. The same login is presented as JSON and as an RFC 5424 syslog line; the extraction stage differs, the XDM assignment stage does not. Auto-detection is deterministic: `scripts/profile_log.py` flags either sample as an authentication event, and `scripts/lint_rule.py` raises advisory WARN-042 (warning only, exit code stays 0) for any mandatory field left unmapped.

## The single canonical event

One Okta SSO login: user `alice@example.com` signs in to a Salesforce app instance from `10.0.0.5`, and it succeeds. Both formats below describe exactly this event, so both rules must produce the same XDM output.

## Format 1 -- native JSON (`okta_systemlog_json_raw`)

The System Log API delivers each event as a JSON object in `_raw_log`:

```json
{
  "uuid": "a1b2c3d4-0000-4f00-9a00-abcdef012345",
  "published": "2026-06-18T12:00:00.000Z",
  "eventType": "user.authentication.sso",
  "displayMessage": "User single sign on to app",
  "outcome": { "result": "SUCCESS" },
  "actor": { "alternateId": "alice@example.com", "displayName": "Alice Admin", "type": "User" },
  "client": {
    "ipAddress": "10.0.0.5",
    "userAgent": { "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0)", "os": "Windows 10", "browser": "CHROME" },
    "geographicalContext": { "city": "London", "country": "United Kingdom" }
  },
  "authenticationContext": { "externalSessionId": "idxSESSION123", "credentialType": "PASSWORD" },
  "target": [ { "id": "0oaApp123", "displayName": "Salesforce", "type": "AppInstance" } ]
}
```

### Field inventory (JSON)

| JSON path | Type | XDM target |
| --- | --- | --- |
| `$.eventType` | string | `xdm.event.original_event_type`, drives `xdm.event.type` |
| `$.outcome.result` | enum string | `xdm.event.outcome` |
| `$.actor.alternateId` | UPN string | `xdm.source.user.upn` (mandatory identity key) |
| `$.actor.displayName` | string | `xdm.source.user.username` (optional display name) |
| `$.client.ipAddress` | string | `xdm.source.ipv4` |
| `$.client.userAgent.rawUserAgent` | string | `xdm.source.user_agent` |
| `$.client.userAgent.os` | string | `xdm.source.host.os`, drives `xdm.source.host.os_family` |
| `$.client.geographicalContext.city` / `.country` | string | `xdm.source.location.city` / `.country` |
| `$.authenticationContext.externalSessionId` | string | `xdm.session_context_id` |
| `$.authenticationContext.credentialType` | enum string | drives `xdm.event.operation` (PASSWORD vs MFA) |
| `$.target[0].id` / `.displayName` | string | `xdm.target.resource.id` / `.name` |

Note the gaps: Okta logs no source port and no target IP / port. Those mandatory fields take their documented placeholders (`to_integer(0)` and the empty string `""`) rather than being dropped.

### The full rule (JSON)

```
[MODEL: dataset = okta_systemlog_json_raw]

// -- Stage 1: Extract from the JSON payload --------------------------------
filter
    _raw_log != null
| alter
    _event = json_extract_scalar(_raw_log, "$.eventType"),
    _result = json_extract_scalar(_raw_log, "$.outcome.result"),
    _upn = json_extract_scalar(_raw_log, "$.actor.alternateId"),
    _display_name = json_extract_scalar(_raw_log, "$.actor.displayName"),
    _src_ip = json_extract_scalar(_raw_log, "$.client.ipAddress"),
    _user_agent = json_extract_scalar(_raw_log, "$.client.userAgent.rawUserAgent"),
    _os = json_extract_scalar(_raw_log, "$.client.userAgent.os"),
    _city = json_extract_scalar(_raw_log, "$.client.geographicalContext.city"),
    _country = json_extract_scalar(_raw_log, "$.client.geographicalContext.country"),
    _session = json_extract_scalar(_raw_log, "$.authenticationContext.externalSessionId"),
    _factor = json_extract_scalar(_raw_log, "$.authenticationContext.credentialType"),
    _app_id = json_extract_scalar(_raw_log, "$.target[0].id"),
    _app_name = json_extract_scalar(_raw_log, "$.target[0].displayName")

// -- Stage 2: Map to XDM (identical to the syslog rule below) ---------------
| alter
    xdm.observer.vendor = "Okta",
    xdm.observer.product = "Identity Cloud",
    // Mandatory authentication-story set (references/authentication-mapping.md)
    xdm.event.type = if(_event != null, "authentication", ""),
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),
    xdm.event.original_event_type = _event,
    xdm.event.operation = if(
        _factor != null and _factor != "PASSWORD", XDM_CONST.OPERATION_TYPE_AUTH_MFA,
        _event != null, XDM_CONST.OPERATION_TYPE_AUTH_LOGIN),
    xdm.event.outcome = if(
        _result ~= "[Ss]uccess", XDM_CONST.OUTCOME_SUCCESS,
        _result != null, XDM_CONST.OUTCOME_FAILED),
    xdm.auth.service = "IDP",
    xdm.source.user.upn = _upn,
    xdm.source.user.identity_type = if(
        _upn != null, XDM_CONST.IDENTITY_TYPE_USER,
        XDM_CONST.IDENTITY_TYPE_UNKNOWN),
    xdm.source.user.user_type = if(
        _upn = null, XDM_CONST.USER_TYPE_REGULAR,
        _upn contains "$", XDM_CONST.USER_TYPE_MACHINE_ACCOUNT,
        lowercase(_upn) ~= "^svc[-_]|service|gserviceaccount",
            XDM_CONST.USER_TYPE_SERVICE_ACCOUNT,
        XDM_CONST.USER_TYPE_REGULAR),
    xdm.source.ipv4 = _src_ip,
    xdm.source.port = to_integer(0),
    xdm.target.ipv4 = "",
    xdm.target.port = to_integer(0),
    xdm.network.ip_protocol = XDM_CONST.IP_PROTOCOL_TCP,
    // Optional enrichment (map when present, omit otherwise)
    xdm.source.user.username = _display_name,
    xdm.source.user_agent = _user_agent,
    xdm.source.host.os = _os,
    xdm.source.host.os_family = if(_os ~= "[Ww]indows", XDM_CONST.OS_FAMILY_WINDOWS),
    xdm.source.location.city = _city,
    xdm.source.location.country = _country,
    xdm.target.resource.id = _app_id,
    xdm.target.resource.name = _app_name,
    xdm.session_context_id = _session
;
```

## Format 2 -- RFC 5424 syslog (`okta_systemlog_syslog_raw`)

A SIEM syslog connector relays the same event as an RFC 5424 line whose message body is the JSON object from Format 1:

```
<134>1 2026-06-18T12:00:00.000Z idp.okta.com okta - - - {"uuid":"a1b2c3d4-0000-4f00-9a00-abcdef012345","published":"2026-06-18T12:00:00.000Z","eventType":"user.authentication.sso","displayMessage":"User single sign on to app","outcome":{"result":"SUCCESS"},"actor":{"alternateId":"alice@example.com","displayName":"Alice Admin","type":"User"},"client":{"ipAddress":"10.0.0.5","userAgent":{"rawUserAgent":"Mozilla/5.0 (Windows NT 10.0)","os":"Windows 10","browser":"CHROME"},"geographicalContext":{"city":"London","country":"United Kingdom"}},"authenticationContext":{"externalSessionId":"idxSESSION123","credentialType":"PASSWORD"},"target":[{"id":"0oaApp123","displayName":"Salesforce","type":"AppInstance"}]}
```

### Pattern selection (syslog)

This is Pattern B (syslog-wrapped): the priority / version / timestamp / host / app-name header sits in front of a structured payload. The only extra step versus Format 1 is peeling the syslog header off to recover the JSON body, after which every `json_extract_scalar` call is identical. Per [extraction-patterns.md](../extraction-patterns.md), strip the wrapper first, then extract.

### The full rule (syslog)

```
[MODEL: dataset = okta_systemlog_syslog_raw]

// -- Stage 1: Strip the RFC 5424 header, recover the JSON body --------------
alter
    _body = arrayindex(regextract(_raw_log, "(\{.*\})\s*$"), 0)

// -- Stage 2: Extract from the recovered JSON ------------------------------
| alter
    _event = json_extract_scalar(_body, "$.eventType"),
    _result = json_extract_scalar(_body, "$.outcome.result"),
    _upn = json_extract_scalar(_body, "$.actor.alternateId"),
    _display_name = json_extract_scalar(_body, "$.actor.displayName"),
    _src_ip = json_extract_scalar(_body, "$.client.ipAddress"),
    _user_agent = json_extract_scalar(_body, "$.client.userAgent.rawUserAgent"),
    _os = json_extract_scalar(_body, "$.client.userAgent.os"),
    _city = json_extract_scalar(_body, "$.client.geographicalContext.city"),
    _country = json_extract_scalar(_body, "$.client.geographicalContext.country"),
    _session = json_extract_scalar(_body, "$.authenticationContext.externalSessionId"),
    _factor = json_extract_scalar(_body, "$.authenticationContext.credentialType"),
    _app_id = json_extract_scalar(_body, "$.target[0].id"),
    _app_name = json_extract_scalar(_body, "$.target[0].displayName")

// -- Stage 3: Map to XDM (byte-for-byte identical to the JSON rule) ---------
| alter
    xdm.observer.vendor = "Okta",
    xdm.observer.product = "Identity Cloud",
    xdm.event.type = if(_event != null, "authentication", ""),
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),
    xdm.event.original_event_type = _event,
    xdm.event.operation = if(
        _factor != null and _factor != "PASSWORD", XDM_CONST.OPERATION_TYPE_AUTH_MFA,
        _event != null, XDM_CONST.OPERATION_TYPE_AUTH_LOGIN),
    xdm.event.outcome = if(
        _result ~= "[Ss]uccess", XDM_CONST.OUTCOME_SUCCESS,
        _result != null, XDM_CONST.OUTCOME_FAILED),
    xdm.auth.service = "IDP",
    xdm.source.user.upn = _upn,
    xdm.source.user.identity_type = if(
        _upn != null, XDM_CONST.IDENTITY_TYPE_USER,
        XDM_CONST.IDENTITY_TYPE_UNKNOWN),
    xdm.source.user.user_type = if(
        _upn = null, XDM_CONST.USER_TYPE_REGULAR,
        _upn contains "$", XDM_CONST.USER_TYPE_MACHINE_ACCOUNT,
        lowercase(_upn) ~= "^svc[-_]|service|gserviceaccount",
            XDM_CONST.USER_TYPE_SERVICE_ACCOUNT,
        XDM_CONST.USER_TYPE_REGULAR),
    xdm.source.ipv4 = _src_ip,
    xdm.source.port = to_integer(0),
    xdm.target.ipv4 = "",
    xdm.target.port = to_integer(0),
    xdm.network.ip_protocol = XDM_CONST.IP_PROTOCOL_TCP,
    xdm.source.user.username = _display_name,
    xdm.source.user_agent = _user_agent,
    xdm.source.host.os = _os,
    xdm.source.host.os_family = if(_os ~= "[Ww]indows", XDM_CONST.OS_FAMILY_WINDOWS),
    xdm.source.location.city = _city,
    xdm.source.location.country = _country,
    xdm.target.resource.id = _app_id,
    xdm.target.resource.name = _app_name,
    xdm.session_context_id = _session
;
```

## Key decisions called out

- Extraction differs, assignment does not. The only delta between the two rules is Stage 1: the syslog rule first runs `regextract(_raw_log, "(\{.*\})\s*$")` to recover the JSON body, then every downstream call matches the JSON rule. This is the whole point of a normalised schema -- once the payload is parsed, the wire format is irrelevant.
- All 14 mandatory fields are mapped in both rules, so the authentication story is created from either feed. WARN-042 stays silent on both because nothing mandatory is missing. This includes the two `xdm.source.user` account-class fields: `identity_type` (`IDENTITY_TYPE_USER` for a real principal) and `user_type` (defaulting to `USER_TYPE_REGULAR`, with the `$` / `svc_` / `service` conventions catching machine and service accounts).
- Placeholders are real, not omissions. Okta logs no source port and no target IP / port, so `xdm.source.port` and `xdm.target.port` take `to_integer(0)` and `xdm.target.ipv4` takes the empty string `""`. Per [authentication-mapping.md](../authentication-mapping.md), a mandatory field must be present even when the source has no value -- dropping it would drop the event from the story.
- `xdm.source.user.upn`, not `username`. The mandatory correlation key is the UPN (`actor.alternateId`). The human-readable `actor.displayName` is mapped to the optional `xdm.source.user.username`; the two are never substituted for each other.
- `xdm.event.type` contains `authentication`. The story keys on this substring, not on a `"AUTH"` category label. The classifier guards on `_event != null` so a malformed row resolves to the empty string rather than a false-positive auth event.
- `xdm.event.operation` follows the credential type. `PASSWORD` maps to `OPERATION_TYPE_AUTH_LOGIN`; any other credential type (a second factor) maps to `OPERATION_TYPE_AUTH_MFA`. `xdm.auth.service = "IDP"` because Okta is validating the credential here.
