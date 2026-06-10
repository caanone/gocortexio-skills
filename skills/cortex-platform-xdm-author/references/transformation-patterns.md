<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Transformation patterns -- applied during XDM mapping

These patterns apply during the mapping stage of a data-model rule, after the extraction has produced underscore-prefixed temps. They are log-type-independent.

## Numeric coercion

The arrow operator (Pattern D) and `json_extract_scalar` (Pattern A) return strings. Wrap in `to_number()` or `to_integer()` when the target XDM field is Number-typed:

- Ports: `xdm.source.port`, `xdm.target.port`, `xdm.intermediate.port`
- Byte counts: `xdm.source.sent_bytes`, `xdm.target.sent_bytes`
- Packet counts: `xdm.source.sent_packets`, `xdm.target.sent_packets`
- Duration: `xdm.event.duration`
- PID: `xdm.source.process.pid`, `xdm.target.process.pid`

```
_src_port = to_integer(Source -> Port)
```

Critical: `to_number()` returns a float. Integer-typed XDM fields MUST be wrapped in `to_integer(to_number(...))` -- see [parser-idioms.md](parser-idioms.md) ERR-015.

## Companion field pairs

When you map one field of a pair, always map the other:

| Pair | Convention |
| --- | --- |
| `xdm.event.outcome` (XDM_CONST) <-> `xdm.observer.action` (String) | Outcome enum next to raw action verb |
| `xdm.event.log_level` (XDM_CONST) <-> `xdm.alert.severity` (String) | Banded level next to human-readable severity |
| `xdm.event.type` (normalised) <-> `xdm.event.original_event_type` (raw) | Always map both when log has an event type |
| `xdm.alert.name` (display) <-> `xdm.alert.original_threat_name` (raw) | Both when log has a threat name |
| `xdm.alert.original_alert_id` <-> `xdm.event.id` | Same value into both when vendor delivers one event ID |
| `xdm.source.user.username` <-> `xdm.source.user.upn` | Mirror when vendor supplies one identity (same for target/intermediate) |
| `xdm.source.host.hostname` <-> `xdm.source.host.fqdn` | Mirror short hostname / FQDN (same for target/intermediate) |
| `xdm.source.user.identifier` <-> `xdm.source.user.username` | Stable user ID + display name when both present |

## String passthrough fallback (mandatory for vendor-text fields)

Every categorical `if()`-chain that assigns to a free-String XDM field carrying vendor text MUST end with a `_field != null, _field` passthrough, so an unmapped vendor value is preserved rather than silently nulled. Without the passthrough, any value your branches did not anticipate vanishes, and the gap only surfaces in production when an analyst notices the field is empty.

```
// WRONG -- unmapped vendor actions are silently dropped
xdm.observer.action = if(
    _action = "ALLOW", "allow",
    _action = "BLOCK", "block")

// RIGHT -- the passthrough preserves anything not explicitly mapped
xdm.observer.action = if(
    _action = "ALLOW", "allow",
    _action = "BLOCK", "block",
    _action != null,   _action)
```

This applies to free-String fields that carry the vendor's own text, such as `xdm.alert.subcategory`, `xdm.observer.action`, `xdm.alert.original_threat_name`, `xdm.event.outcome_reason`. Two exceptions:

- Closed-list `XDM_CONST` targets (`xdm.event.outcome`, `xdm.alert.category`, `xdm.network.http.method`, and the rest in the XDM_CONST-required table below) keep OMITTING the default branch, so an unmatched value resolves to null. A raw string would break the enum type.
- Band-vocabulary String fields like `xdm.alert.severity` floor to a band (`_field != null, "Low"`) or omit the default; they NEVER echo the raw value, because an arbitrary string is not a valid band (see the log-level vocabulary rule).

## Array field construction

Array-typed XDM fields (marked `(Array)` in [xdm-schema.md](xdm-schema.md)) MUST use `arraycreate()`. Always null-guard:

```
if(_value != null, arraycreate(_value), null)
```

Common array fields:

- `xdm.source.host.ipv4_addresses`, `xdm.target.host.ipv4_addresses`
- `xdm.source.host.mac_addresses`, `xdm.target.host.mac_addresses`
- `xdm.source.user.groups`, `xdm.source.user.roles`
- `xdm.email.recipients` -- despite not being labelled Array in the schema, it requires `arraycreate()` (see [xdm-schema.md](xdm-schema.md) notes).

Multi-IP pattern (coalesce + arraycreate together):

```
| alter
    _src_ip     = Source -> IP,
    _src_alt_ip = Source -> AlternateIP
| alter
    _resolved_src_ip = coalesce(_src_ip, _src_alt_ip)
| alter
    xdm.source.ipv4               = _resolved_src_ip,
    xdm.source.host.ipv4_addresses = if(_resolved_src_ip != null,
                                        arraycreate(_resolved_src_ip),
                                        null)
```

`_src_alt_ip` is consumed by the `coalesce`, so it is not an unused temp.

## XDM_CONST-required fields

These fields MUST use XDM_CONST enum values via `if()` chains, never raw strings:

| Field | Constant group |
| --- | --- |
| `xdm.event.outcome` | `XDM_CONST.OUTCOME_*` |
| `xdm.event.log_level` | `XDM_CONST.LOG_LEVEL_*` |
| `xdm.event.operation` | `XDM_CONST.OPERATION_TYPE_*` |
| `xdm.network.http.method` | `XDM_CONST.HTTP_METHOD_*` |
| `xdm.network.http.response_code` | `XDM_CONST.HTTP_RSP_CODE_*` |
| `xdm.{source,target}.cloud.provider` | `XDM_CONST.CLOUD_PROVIDER_*` |
| `xdm.{source,target}.cloud.service` | `XDM_CONST.CLOUD_SERVICE_TYPE_*` |
| `xdm.{source,target}.user.identity_type` | `XDM_CONST.IDENTITY_TYPE_*` |
| `xdm.{source,target}.host.os_family` | `XDM_CONST.OS_FAMILY_*` |
| `xdm.network.ip_protocol` | `XDM_CONST.IP_PROTOCOL_*` |
| `xdm.alert.mitre_tactics` | `XDM_CONST.MITRE_TACTIC_*` |
| `xdm.alert.mitre_techniques` | `XDM_CONST.MITRE_TECHNIQUE_*` |

```
// WRONG
xdm.network.http.method = _http_method

// RIGHT
xdm.network.http.method = if(
    _http_method = "GET",    XDM_CONST.HTTP_METHOD_GET,
    _http_method = "POST",   XDM_CONST.HTTP_METHOD_POST,
    _http_method = "PUT",    XDM_CONST.HTTP_METHOD_PUT,
    _http_method = "DELETE", XDM_CONST.HTTP_METHOD_DELETE)
```

Raw strings on XDM_CONST fields cause silent data loss in Cortex -- the value is dropped.

### Default branch rule for XDM_CONST if-chains

The default (final) branch of an `if()`-chain for an XDM_CONST field must be another XDM_CONST value or be omitted entirely -- never a raw string.

```
// WRONG -- raw string default
xdm.alert.category = if(
    _cat = "sql_injection", XDM_CONST.THREAT_CATEGORY_SQL_INJECTION,
    _cat != null, _cat)                    // raw string default!

// RIGHT
xdm.alert.category = if(
    _cat = "sql_injection", XDM_CONST.THREAT_CATEGORY_SQL_INJECTION,
    _cat = "cryptominer",   XDM_CONST.THREAT_CATEGORY_CRYPTOMINER)
```

If no matching constant exists for the default case, omit the default branch so unmatched values produce null (safe). Use `xdm.alert.subcategory` (String type) for the raw vendor text as a fallback.

If unsure which constant to use, OMIT the field entirely. See [pitfall-traps.md](pitfall-traps.md) for the OMIT-and-fall-back rule.

## Banded numeric scoring (mandatory for `score` fields)

If a vendor source field name contains `"score"` (e.g. `risk_score`, `riskScore`, `threat_score`, `severity_score`, `confidence_score`, `alert_score`) OR is otherwise a numeric severity scale (0-100, 0-10, 1-5), you MUST apply banded scoring: an `if`-chain mapping thresholds to `"Critical"` / `"High"` / `"Medium"` / `"Low"` for `xdm.alert.severity` AND a parallel `XDM_CONST.LOG_LEVEL_*` `if`-chain into `xdm.event.log_level`.

```
xdm.alert.severity = if(
    _score >= 80, "Critical",
    _score >= 50, "High",
    _score >= 30, "Medium",
    _score != null, "Low"),
xdm.event.log_level = if(
    _score >= 80, XDM_CONST.LOG_LEVEL_CRITICAL,
    _score >= 50, XDM_CONST.LOG_LEVEL_ERROR,
    _score >= 30, XDM_CONST.LOG_LEVEL_WARNING,
    _score != null, XDM_CONST.LOG_LEVEL_INFORMATIONAL)
```

NEVER assign the raw score via `to_string()` or as a number to `xdm.alert.severity`. `xdm.alert.severity` is a categorical String field; an unbanded number-string is a silent regression that the linter cannot catch.

This rule does NOT apply to non-numeric severity columns (already-banded labels like `"low"` / `"medium"` / `"high"` use case-normalisation instead -- see "Severity normalisation" below).

## Severity normalisation (for already-banded labels)

```
xdm.alert.severity = if(
    _risk_level = "low",      "Low",
    _risk_level = "medium",   "Medium",
    _risk_level = "high",     "High",
    _risk_level = "critical", "Critical",
    _risk_level != null,      _risk_level)
```

The `_risk_level != null, _risk_level` floor is safe here because the source vocabulary IS the band vocabulary: an unmatched value is still a band word. Do NOT use a raw passthrough when the source vocabulary is something else, such as the log-level words below.

## Log-level vocabulary (severity words that are really log levels)

Some vendors put log-level words in the severity field: `debug`, `info` / `informational`, `notice`, `warning`, `error`, `critical`. These are log levels, not alert severities. Band them into `xdm.alert.severity` (Informational / Low / Medium / High / Critical) AND map them to `xdm.event.log_level` via `XDM_CONST.LOG_LEVEL_*`. Never echo a log-level word -- `"Warning"`, `"Error"`, `"Notice"`, `"Debug"` -- into `xdm.alert.severity`. That field is a band scale, not a syslog level, so a raw log-level word there is a silent miscategorisation that downstream severity filters miss.

```
xdm.alert.severity = if(
    _level = "debug",    "Informational",
    _level = "info",     "Informational",
    _level = "notice",   "Low",
    _level = "warning",  "Medium",
    _level = "error",    "High",
    _level = "critical", "Critical",
    _level != null,      "Low"),
xdm.event.log_level = if(
    _level = "debug",    XDM_CONST.LOG_LEVEL_INFORMATIONAL,
    _level = "info",     XDM_CONST.LOG_LEVEL_INFORMATIONAL,
    _level = "notice",   XDM_CONST.LOG_LEVEL_NOTICE,
    _level = "warning",  XDM_CONST.LOG_LEVEL_WARNING,
    _level = "error",    XDM_CONST.LOG_LEVEL_ERROR,
    _level = "critical", XDM_CONST.LOG_LEVEL_CRITICAL)
```

The `xdm.alert.severity` chain ends with a `_level != null, "Low"` band floor, NOT a raw passthrough, so an unrecognised value still lands on a real band instead of leaking a log-level word. The `xdm.event.log_level` chain omits the default branch: it is an `XDM_CONST` closed list, so an unmatched value resolves to null (safe). The linter flags WARN-037 when a log-level word is assigned to `xdm.alert.severity`.

## Categorical enum array -> THREAT_CATEGORY scalar

If the log has an array of vendor category strings -- columns named `categories`, `threat_categories`, `classifications`, `tags`, `labels`, `attack_categories` -- you MUST first attempt to map them to `xdm.alert.category` via `XDM_CONST.THREAT_CATEGORY_*` using the "Scalar-from-array via arrayindex + arrayfilter" pattern in [extraction-patterns.md](extraction-patterns.md).

Do NOT default-route the array into `xdm.alert.subcategory` via `arraystring()` and then claim "no `XDM_CONST.THREAT_CATEGORY_*` applies" -- the THREAT_CATEGORY enum has 30+ members. Only fall back to `xdm.alert.subcategory` when EVERY category string fails a case-insensitive substring/regex match against the THREAT_CATEGORY tokens. Preserve the full joined text in `xdm.event.description` either way.

## Array MITRE mapping (arraymap, not arraycreate wrapper)

When the log carries an array of MITRE technique IDs (e.g. `["T1059", "T1078"]`) and you must map each ID to its `XDM_CONST.MITRE_TECHNIQUE_*` constant, use `arraymap` with an inner if-chain. The result of `arraymap` IS already an array. Do NOT wrap in `arraycreate()`.

```
// CORRECT
xdm.alert.mitre_techniques = arraymap(
    _mitre_technique_ids,
    if("@element" = "T1059", XDM_CONST.MITRE_TECHNIQUE_COMMAND_AND_SCRIPTING_INTERPRETER,
    if("@element" = "T1078", XDM_CONST.MITRE_TECHNIQUE_VALID_ACCOUNTS,
    if("@element" = "T1110", XDM_CONST.MITRE_TECHNIQUE_BRUTE_FORCE,
        null))))
```

The `XDM_CONST.MITRE_TECHNIQUE_*` constants use the canonical MITRE technique NAME, not the technique ID. E.g. T1078 maps to `XDM_CONST.MITRE_TECHNIQUE_VALID_ACCOUNTS` (no `T1078_` prefix). NEVER prepend the T-id to the constant name -- that creates an invented constant.

```
// WRONG -- double-wrap; produces array-of-arrays
xdm.alert.mitre_techniques = arraycreate(
    arraymap(_mitre_technique_ids, if(...)))

// WRONG -- raw string default; breaks XDM_CONST type
arraymap(_ids, if("@element" = "T1059",
    XDM_CONST.MITRE_TECHNIQUE_COMMAND_AND_SCRIPTING_INTERPRETER,
    "@element"))
```

Tactic IDs follow the same pattern with `XDM_CONST.MITRE_TACTIC_*` into `xdm.alert.mitre_tactics`.

## Single-entity mirroring (when source and target are the same)

When a payload has only one IP or one user, map to BOTH source and target for maximum correlation coverage in XSIAM:

```
xdm.source.ipv4          = _client_ip,
xdm.target.ipv4          = _client_ip,
xdm.source.user.username = _user,
xdm.target.user.username = _user
```

Only do this when there is genuinely a single entity. When source and target are different (email sender vs recipient, web client vs upstream server), do NOT mirror.

## One-sided source/target mirroring (single-actor detections)

Many vendor detections describe a SINGLE actor -- the offender, attacker, principal -- and never deliver a normalised counterparty. ExtraHop RevealX, SentinelOne, Vectra, Darktrace and most NDR products behave this way. Cortex correlation pivots on either `xdm.source.` OR `xdm.target.` depending on the dashboard, so a one-sided detection populated only on one half is half-invisible to the analyst.

THE RULE: When the vendor delivers ONE actor and no counterparty, mirror the actor's identity into BOTH `xdm.source.` AND `xdm.target.`.

Explicit mirror pair list (six pairs, no inference):

- `xdm.source.ipv4` <-> `xdm.target.ipv4`
- `xdm.source.host.ipv4_addresses` <-> `xdm.target.host.ipv4_addresses`
- `xdm.source.host.hostname` <-> `xdm.target.host.hostname`
- `xdm.source.user.username` <-> `xdm.target.user.username`
- `xdm.source.user.upn` <-> `xdm.target.user.upn`
- `xdm.source.is_internal_ip` <-> `xdm.target.is_internal_ip`

Do NOT mirror role-specific fields (`sent_bytes`, `port`, `process.*`, `zone`, `vlan`, `agent.*`) -- those are direction-specific and a wrong-side copy is worse than null.

```
| alter
    xdm.source.ipv4               = _offender_ip,
    xdm.source.user.username      = _offender_username,
    xdm.source.user.upn           = _offender_username,
    xdm.source.is_internal_ip     = _offender_is_internal,
    xdm.target.ipv4               = _offender_ip,
    xdm.target.user.username      = _offender_username,
    xdm.target.user.upn           = _offender_username,
    xdm.target.is_internal_ip     = _offender_is_internal;
```

Why not `xdm.{source,target}.is_external`? That path does NOT exist. The only canonical sink for an external/internal boolean is `is_internal_ip`. When the vendor exposes `external` (or equivalent), invert with:

```
_is_internal = if(
    to_boolean(_external) = true,  to_boolean("false"),
    to_boolean(_external) = false, to_boolean("true"))
```

Then mirror `_is_internal` into BOTH `xdm.source.is_internal_ip` and `xdm.target.is_internal_ip`.

When NOT to mirror:

- The vendor delivers BOTH a real source and a real target (firewall flows, proxy logs, EDR file-write events). Map each side from its own log fields.
- The vendor delivers a victim entity with non-null identifiers. Use those.

Stage boundary caveat: Mirroring lives in the FINAL `alter` stage (the `xdm.*` drain stage), NEVER in the same `alter` that derives the offender temp being mirrored. Cortex evaluates all targets in one `alter` in parallel ([parser-idioms.md](parser-idioms.md) idiom (xi)), so `xdm.source.ipv4 = _offender_ip` in the same stage that defines `_offender_ip` is rejected as "unknown field `_offender_ip`". Always: derive in stage N, drain + mirror in stage N+1.

## Defensive `coalesce(PascalCase, camelCase)`

When the XSIAM parser may produce field names in either PascalCase or camelCase (common with AWS, Azure, GCP sources), use `coalesce` on both forms throughout:

```
finding_resource     = coalesce(Resource, resource),
finding_id           = coalesce(Id, id),
resource_instance_id = coalesce(
    finding_resource -> InstanceDetails.InstanceId,
    finding_resource -> instanceDetails.instanceId)
```

## Directional IP/port resolution

When a finding reports both local and remote IPs with a direction indicator (`INBOUND` / `OUTBOUND`), resolve source and target based on direction:

```
source_ipv4 = if(is_inbound, remote_ip, is_outbound, local_ip, fallback_ip)
target_ipv4 = if(is_inbound, local_ip,  is_outbound, remote_ip)
```

## Transitive field usage

Intermediary fields may feed into other intermediary fields before reaching an XDM assignment. This is valid as long as the chain terminates in an `xdm.*` assignment:

```
http_code = to_integer(raw_status_code),
xdm.network.http.response_code = if(
    http_code = 200, XDM_CONST.HTTP_RSP_CODE_OK, ...)
```

If `http_code` were extracted but NOT mapped, Cortex rejects the rule.

## Identity-type mapping

Common vendor identity tokens map to `XDM_CONST.IDENTITY_TYPE_*` as follows:

| Vendor token | Constant |
| --- | --- |
| `ServiceAccount`, `service_account`, `svc-*` | `IDENTITY_TYPE_MACHINE` |
| `Machine`, `machine`, `system` | `IDENTITY_TYPE_MACHINE` |
| `User`, `user`, `human` | `IDENTITY_TYPE_USER` |
| `Admin`, `admin`, `root` | `IDENTITY_TYPE_BUILTIN` |

Do NOT map `ServiceAccount` to `IDENTITY_TYPE_USER`.

## Authentication and MFA mapping

Authentication logs have dedicated structured homes under `xdm.auth.*`. These fields are easy to miss because the anchor index has thin precedent for them -- check the schema, not just the anchor lookup, before declaring a field unmapped:

| Vendor field | XDM target |
| --- | --- |
| `mfa_method`, `mfa_type`, `factor` | `xdm.auth.mfa.method` (String) |
| `mfa_provider` | `xdm.auth.mfa.provider` (String) |
| `is_mfa_needed`, `mfa_required` | `xdm.auth.is_mfa_needed` (Boolean -- wrap with `to_boolean(...)`) |
| `auth_method`, `authentication_method` | `xdm.auth.auth_method` (String) |

Companion classification: when the log is an authentication event, set `xdm.event.operation` alongside `xdm.event.type = "AUTH"`. Use `XDM_CONST.OPERATION_TYPE_AUTH_MFA` when the event involves MFA, otherwise `XDM_CONST.OPERATION_TYPE_AUTH_LOGIN`:

```
xdm.event.type = "AUTH",
xdm.event.operation = if(
    _mfa_method != null, XDM_CONST.OPERATION_TYPE_AUTH_MFA,
    XDM_CONST.OPERATION_TYPE_AUTH_LOGIN),
xdm.auth.mfa.method = _mfa_method,
xdm.auth.is_mfa_needed = to_boolean(_mfa_required)
```

Never bury `mfa_method` (or device / OS detail) in `xdm.event.description` -- these values have structured homes, and a description-only copy is invisible to downstream queries. The description summarises; it never substitutes (see "Structured event description" below).

## Structured event description

Emit `xdm.event.description` by default: a deterministic human-readable summary built with `concat()` over the identifying fields. It gives the analyst a one-line gist in the alert view and a consistent free-text search target. It is an ADDITION to the structured XDM fields, never a substitute -- map each value to its own queryable field first, then summarise. Never bury data in the description that belongs in a field of its own.

Build the summary with `concat()` and conditional sections:

```
xdm.event.description = concat(
    "Vendor ", eventType,
    if(direction != null, concat(" (", direction, ")"), ""),
    if(Subject != null,   concat(" | Subject: ", Subject), ""),
    if(Action != null,    concat(" | Action: ", Action), ""))
```

Remember idiom (xii): variables whose only consumer is inside a `concat()` body do NOT count toward reach. Inline the derivation directly, or drain through a bareword identity assignment first.

## No duplicate assignments

Never assign the same temp variable to two different XDM fields unless both fields genuinely require the same value (e.g. `xdm.event.id` and `xdm.alert.original_alert_id` both receiving `_event_id` is acceptable). If you find yourself assigning the same value to two XDM fields that serve different semantic purposes, one of them is wrong.

## Event type vs original event type

- `xdm.event.type` = normalised category: use short generic labels like `"ALERT"`, `"NETWORK"`, `"AUDIT"`, `"AUTH"`. This is the Cortex correlation key.
- `xdm.event.original_event_type` = raw vendor event type exactly as it appears in the log (e.g. `"WAF_BLOCK"`, `"THREAT_DETECT"`, `"LOGIN_FAILED"`).

Always map BOTH when the log provides an event type field.
