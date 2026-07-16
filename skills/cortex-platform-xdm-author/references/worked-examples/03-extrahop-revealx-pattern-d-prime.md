<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Walkthrough 3 -- ExtraHop RevealX (Pattern D' role-filtered array)

Vendor / product / dataset: ExtraHop / RevealX / `extrahop_revealx_raw`.

What the rule does: maps ExtraHop RevealX detection events to the XDM schema. RevealX detections include a `participants[]` array where each element has a `role` (`offender` or `victim`), and a `categories[]` array carrying threat-category labels that map to closed-list `XDM_CONST.THREAT_CATEGORY_*` constants.

## Synthesised raw log sample

RevealX emits detection events as JSON-with-nested-arrays. On the LIVE TENANT the nested array columns (`categories`, `participants`, `mitre_tactics`, `mitre_techniques`) arrive as JSON STRINGS even though the producer schema documents them as native arrays -- this is the central correctness doctrine the rule enforces.

```json
{
  "id": 12884912070,
  "type": "ssh_brute_force",
  "title": "SSH Brute Force Attempt",
  "description": "Multiple failed SSH logins from a single client",
  "url": "https://revealx.acme.local/detections/12884912070",
  "risk_score": 72,
  "start_time": 1744720000000,
  "end_time": 1744720180000,
  "tmp_reporting_device_ip": "10.0.50.5",
  "appliance_id": 1138,
  "categories": ["brute_force", "credential_attack"],
  "mitre_tactics": [{"id": "TA0006"}],
  "mitre_techniques": [{"id": "T1110"}],
  "properties": {
    "risk_event_name": "ssh_brute_force"
  },
  "participants": [
    {"role": "offender", "object_type": "ipaddr", "object_value": "198.51.100.42",
     "hostname": null, "username": null, "external": true, "object_id": 4001},
    {"role": "victim",   "object_type": "device", "object_value": "10.0.20.15",
     "hostname": "auth-server.acme.local", "username": null,
     "external": false, "object_id": 8202}
  ]
}
```

Note: `tmp_reporting_device_ip` is a parser-stamped `_` anchor, not a raw column the MODEL can read -- like `tmp_detection_category`, the rule leaves it alone, since reading a parser-only `_` column would be an ERR-027 unknown field. `properties` arrives as a typed Object (use scalar `->`). All four of `categories` / `participants` / `mitre_tactics` / `mitre_techniques` arrive as JSON strings on the live tenant -- the `-> []` cast is mandatory before any array function.

## Field inventory

Top-level columns:

| Column | Shape | Notes |
| --- | --- | --- |
| `id` | integer | Detection ID. Stringified for `xdm.event.id`. |
| `type` | string | Internal event-type token. |
| `title` | string | Human-readable detection name. |
| `risk_score` | integer (0-99) | Numeric risk; MUST be banded. |
| `start_time`, `end_time` | epoch ms | Duration derived via `subtract()`. |
| `categories` | JSON-string-of-array | `-> []` cast required. |
| `participants` | JSON-string-of-array-of-objects | Per-scalar projection required. |
| `mitre_tactics` / `mitre_techniques` | JSON-string-of-array-of-objects | `arraymap(... -> [], "@element" -> id)` to extract IDs. |
| `properties` | typed Object | Scalar `->` accessor. |

## Pattern selection

Two patterns at once:

1. Pattern A (`json_extract_scalar`-equivalent via `properties -> risk_event_name`) for the `properties` object.
2. Pattern D' (role-filtered array of objects, per-scalar projection) for `participants[]`.

The Pattern D' shape is critical: for each scalar you need from the filtered role, you write a separate `arraymap(participants -> [], if("@element" -> role = "offender", "@element" -> <field>, null))` then `arrayfilter("@element" != null)` then `arrayindex(..., 0)`. You do NOT bind a struct array to a temp and re-project -- the Cortex parser rejects that (ERR-017).

## Field-anchor lookups

Most fields here are RevealX-specific (`risk_score`, `risk_event_name`, `object_value`); the anchor index won't carry them. The rule reads them directly from the JSON shape:

```sh
$ python3 scripts/lookup_anchor.py risk_score
  -> no candidate (vendor-specific; route to xdm.alert.severity via banding)

$ python3 scripts/lookup_anchor.py object_value
  -> no candidate (vendor-specific shape; route by SHAPE -- IPv4 regex)
```

For the well-known sinks (`username`, `hostname`), the index identifies the canonical XDM paths -- but here the values come from the projected participant array, not from named top-level columns.

## The full rule

```
// ExtraHop RevealX -- XDM Data Model Rule
// Dataset: extrahop_revealx_raw
// Vendor: ExtraHop | Product: RevealX
//
// Maps ExtraHop RevealX detection events to the Cortex XDM schema.
//
// CRITICAL DOCTRINE -- parser stage and datamodel stage see DIFFERENT
// shapes of the same nested columns. The PARSER reads the raw ingest
// payload where `categories`, `participants`, `mitre_tactics` and
// `mitre_techniques` are still native Arrays. This data model rule
// reads the persisted dataset where the same four columns have been
// serialised to JSON STRINGS on write. Each one fails save here with
// "Field <col> for function arraymap is invalid. Expected array but
// received string" when read as a bare column reference, so all four
// MUST go through the `-> []` JSON-array cast before any array-function
// call in this file.
//
// `properties` is the only nested column that arrives as a typed
// Object in BOTH stages -- read with the scalar `->` field accessor
// here (`properties -> risk_event_name`).
//
// Participant projection -- six payload shapes are observed in the
// wild and all are handled (single offender + victim, multiple
// offenders no victims, multiple victims with mirroring, victim-only,
// object_id-only rows where IP and hostname are absent, sibling
// `hostname` field carrying a DNS name when `object_value` is an IP).
//
// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later

[MODEL: dataset = extrahop_revealx_raw]

alter
    tmp_event_id = to_string(id),
    tmp_event_type = type,
    tmp_alert_title = title,
    tmp_alert_description = description,
    tmp_alert_url = url,
    tmp_risk_score = risk_score,
    tmp_start_ms = start_time,
    tmp_end_ms = end_time,
    tmp_appliance_id = to_string(appliance_id),
    tmp_categories_arr = categories -> [],
    tmp_risk_event_name = properties -> risk_event_name,
    tmp_mitre_tactic_ids = arraymap(mitre_tactics -> [], "@element" -> id),
    tmp_mitre_technique_ids = arraymap(mitre_techniques -> [], "@element" -> id),
    // Per-role array projections of participants[]. Per-scalar
    // projection: arraymap with inner if() returning the scalar when
    // role matches, then arrayfilter to drop nulls.
    tmp_offender_role_marks = arrayfilter(arraymap(participants -> [],
        if("@element" -> role = "offender", "1", null)), "@element" != null),
    tmp_offender_ip_seq = arrayfilter(arraymap(participants -> [],
        if("@element" -> role = "offender", "@element" -> object_value, null)),
        "@element" ~= "^[0-9]{1,3}([.][0-9]{1,3}){3}$"),
    tmp_offender_hostname_seq = arrayfilter(arraymap(participants -> [], if(
        "@element" -> role = "offender" and "@element" -> hostname != null, "@element" -> hostname,
        "@element" -> role = "offender" and "@element" -> object_value != null
            and not("@element" -> object_value ~= "^[0-9]{1,3}([.][0-9]{1,3}){3}$"), "@element" -> object_value,
        null)), "@element" != null),
    tmp_offender_username_seq = arrayfilter(arraymap(participants -> [],
        if("@element" -> role = "offender", "@element" -> username, null)),
        "@element" != null),
    tmp_offender_external_seq = arrayfilter(arraymap(participants -> [],
        if("@element" -> role = "offender", "@element" -> external, null)),
        "@element" != null),
    tmp_offender_object_id_seq = arrayfilter(arraymap(participants -> [],
        if("@element" -> role = "offender", to_string("@element" -> object_id), null)),
        "@element" != null),
    tmp_victim_role_marks = arrayfilter(arraymap(participants -> [],
        if("@element" -> role = "victim", "1", null)), "@element" != null),
    tmp_victim_ip_seq = arrayfilter(arraymap(participants -> [],
        if("@element" -> role = "victim", "@element" -> object_value, null)),
        "@element" ~= "^[0-9]{1,3}([.][0-9]{1,3}){3}$"),
    tmp_victim_hostname_seq = arrayfilter(arraymap(participants -> [], if(
        "@element" -> role = "victim" and "@element" -> hostname != null, "@element" -> hostname,
        "@element" -> role = "victim" and "@element" -> object_value != null
            and not("@element" -> object_value ~= "^[0-9]{1,3}([.][0-9]{1,3}){3}$"), "@element" -> object_value,
        null)), "@element" != null),
    tmp_victim_username_seq = arrayfilter(arraymap(participants -> [],
        if("@element" -> role = "victim", "@element" -> username, null)),
        "@element" != null),
    tmp_victim_external_seq = arrayfilter(arraymap(participants -> [],
        if("@element" -> role = "victim", "@element" -> external, null)),
        "@element" != null),
    tmp_victim_object_id_seq = arrayfilter(arraymap(participants -> [],
        if("@element" -> role = "victim", to_string("@element" -> object_id), null)),
        "@element" != null)

// Stage 2a -- LEAF temps (depend on stage-1 outputs, not each other).
| alter
    tmp_offender_count = array_length(tmp_offender_role_marks),
    tmp_victim_count = array_length(tmp_victim_role_marks),
    tmp_offender_ip_first = arrayindex(tmp_offender_ip_seq, 0),
    tmp_offender_hostname_first = arrayindex(tmp_offender_hostname_seq, 0),
    tmp_offender_username_first = arrayindex(tmp_offender_username_seq, 0),
    tmp_offender_external_first = arrayindex(tmp_offender_external_seq, 0),
    tmp_offender_object_id_first = arrayindex(tmp_offender_object_id_seq, 0),
    tmp_victim_ip_first = arrayindex(tmp_victim_ip_seq, 0),
    tmp_victim_hostname_first = arrayindex(tmp_victim_hostname_seq, 0),
    tmp_victim_username_first = arrayindex(tmp_victim_username_seq, 0),
    tmp_victim_external_first = arrayindex(tmp_victim_external_seq, 0),
    tmp_victim_object_id_first = arrayindex(tmp_victim_object_id_seq, 0),
    tmp_duration_ms = to_integer(subtract(to_number(tmp_end_ms), to_number(tmp_start_ms))),
    // Pre-derive banded severity / log level for single-line drains.
    tmp_severity = if(
        tmp_risk_score >= 80, "Critical",
        tmp_risk_score >= 50, "High",
        tmp_risk_score >= 30, "Medium",
        tmp_risk_score != null, "Low"),
    tmp_log_level = if(
        tmp_risk_score >= 80, XDM_CONST.LOG_LEVEL_CRITICAL,
        tmp_risk_score >= 50, XDM_CONST.LOG_LEVEL_ERROR,
        tmp_risk_score >= 30, XDM_CONST.LOG_LEVEL_WARNING,
        tmp_risk_score != null, XDM_CONST.LOG_LEVEL_INFORMATIONAL),
    tmp_risk_band = if(tmp_risk_score >= 70, "HIGH",
                    tmp_risk_score >= 30, "MEDIUM",
                    tmp_risk_score != null, "LOW"),
    tmp_category_const = arrayindex(arrayfilter(arraymap(tmp_categories_arr, if(
        "@element" ~= "(?i)brute",       XDM_CONST.THREAT_CATEGORY_BRUTE_FORCE,
        "@element" ~= "(?i)phish",       XDM_CONST.THREAT_CATEGORY_PHISHING,
        "@element" ~= "(?i)dos|ddos",    XDM_CONST.THREAT_CATEGORY_DOS,
        "@element" ~= "(?i)botnet",      XDM_CONST.THREAT_CATEGORY_BOTNET,
        "@element" ~= "(?i)backdoor",    XDM_CONST.THREAT_CATEGORY_BACKDOOR,
        "@element" ~= "(?i)spyware",     XDM_CONST.THREAT_CATEGORY_SPYWARE,
        "@element" ~= "(?i)cryptominer|miner", XDM_CONST.THREAT_CATEGORY_CRYPTOMINER,
        "@element" ~= "(?i)exfil|data",  XDM_CONST.THREAT_CATEGORY_DATA_THEFT,
        "@element" ~= "(?i)code",        XDM_CONST.THREAT_CATEGORY_CODE_EXECUTION,
        "@element" ~= "(?i)dns",         XDM_CONST.THREAT_CATEGORY_DNS,
        "@element" ~= "(?i)hacktool|tool", XDM_CONST.THREAT_CATEGORY_HACKTOOL,
        "@element" ~= "(?i)post.?expl",  XDM_CONST.THREAT_CATEGORY_POST_EXPLOITATION,
        "@element" ~= "(?i)protocol",    XDM_CONST.THREAT_CATEGORY_PROTOCOL_ANOMALY)),
        "@element" != null), 0),
    tmp_mitre_tactics_const = arraymap(tmp_mitre_tactic_ids, if(
        "@element" = "TA0001", XDM_CONST.MITRE_TACTIC_INITIAL_ACCESS,
        "@element" = "TA0002", XDM_CONST.MITRE_TACTIC_EXECUTION,
        "@element" = "TA0003", XDM_CONST.MITRE_TACTIC_PERSISTENCE,
        "@element" = "TA0004", XDM_CONST.MITRE_TACTIC_PRIVILEGE_ESCALATION,
        "@element" = "TA0005", XDM_CONST.MITRE_TACTIC_DEFENSE_EVASION,
        "@element" = "TA0006", XDM_CONST.MITRE_TACTIC_CREDENTIAL_ACCESS,
        "@element" = "TA0007", XDM_CONST.MITRE_TACTIC_DISCOVERY,
        "@element" = "TA0008", XDM_CONST.MITRE_TACTIC_LATERAL_MOVEMENT,
        "@element" = "TA0009", XDM_CONST.MITRE_TACTIC_COLLECTION,
        "@element" = "TA0010", XDM_CONST.MITRE_TACTIC_EXFILTRATION,
        "@element" = "TA0011", XDM_CONST.MITRE_TACTIC_COMMAND_AND_CONTROL,
        "@element" = "TA0040", XDM_CONST.MITRE_TACTIC_IMPACT,
        "@element" = "TA0042", XDM_CONST.MITRE_TACTIC_RESOURCE_DEVELOPMENT,
        "@element" = "TA0043", XDM_CONST.MITRE_TACTIC_RECONNAISSANCE)),
    tmp_mitre_techniques_const = arraymap(tmp_mitre_technique_ids, if(
        "@element" = "T1078", XDM_CONST.MITRE_TECHNIQUE_VALID_ACCOUNTS,
        "@element" = "T1098", XDM_CONST.MITRE_TECHNIQUE_ACCOUNT_MANIPULATION,
        "@element" = "T1110", XDM_CONST.MITRE_TECHNIQUE_BRUTE_FORCE,
        "@element" = "T1114", XDM_CONST.MITRE_TECHNIQUE_EMAIL_COLLECTION,
        "@element" = "T1087", XDM_CONST.MITRE_TECHNIQUE_ACCOUNT_DISCOVERY,
        "@element" = "T1190", XDM_CONST.MITRE_TECHNIQUE_EXPLOITATION_OF_REMOTE_SERVICES,
        "@element" = "T1133", XDM_CONST.MITRE_TECHNIQUE_EXTERNAL_REMOTE_SERVICES,
        "@element" = "T1566", XDM_CONST.MITRE_TECHNIQUE_PHISHING,
        "@element" = "T1136", XDM_CONST.MITRE_TECHNIQUE_CREATE_ACCOUNT,
        "@element" = "T1071", XDM_CONST.MITRE_TECHNIQUE_WEB_SERVICE))

// Stage 2b -- DEPENDENT temps (reference 2a outputs only).
| alter
    tmp_source_is_internal = if(
        tmp_offender_count > 0 and to_boolean(tmp_offender_external_first) = true, to_boolean("false"),
        tmp_offender_count > 0 and to_boolean(tmp_offender_external_first) = false, to_boolean("true")),
    tmp_target_is_internal = if(
        tmp_victim_count > 0 and to_boolean(tmp_victim_external_first) = true, to_boolean("false"),
        tmp_victim_count > 0 and to_boolean(tmp_victim_external_first) = false, to_boolean("true"),
        tmp_victim_count = 0 and tmp_offender_count > 0 and to_boolean(tmp_offender_external_first) = true, to_boolean("false"),
        tmp_victim_count = 0 and tmp_offender_count > 0 and to_boolean(tmp_offender_external_first) = false, to_boolean("true")),
    tmp_target_ip_first = if(tmp_victim_count > 0, tmp_victim_ip_first, tmp_offender_ip_first),
    tmp_target_hostname_first = if(tmp_victim_count > 0, tmp_victim_hostname_first, tmp_offender_hostname_first),
    tmp_target_username_first = if(tmp_victim_count > 0, tmp_victim_username_first, tmp_offender_username_first),
    tmp_target_ip_arr = if(tmp_victim_count > 0, tmp_victim_ip_seq, tmp_offender_ip_seq),
    tmp_source_device_id = if(tmp_offender_count > 0,
        if(tmp_offender_ip_first != null, null,
            if(tmp_offender_hostname_first != null, null, tmp_offender_object_id_first)),
        null),
    tmp_target_device_id = if(tmp_victim_count > 0,
        if(tmp_victim_ip_first != null, null,
            if(tmp_victim_hostname_first != null, null, tmp_victim_object_id_first)),
        if(tmp_offender_count > 0,
            if(tmp_offender_ip_first != null, null,
                if(tmp_offender_hostname_first != null, null, tmp_offender_object_id_first)),
            null)),
    tmp_description = concat(
        coalesce(tmp_alert_title, "RevealX detection"),
        if(tmp_risk_band != null, concat(" | Risk band: ", tmp_risk_band), ""),
        if(tmp_categories_arr != null, concat(" | Categories: ", arraystring(tmp_categories_arr, ", ")), ""),
        if(tmp_offender_username_first != null, concat(" | Offender user: ", tmp_offender_username_first), ""),
        if(tmp_offender_ip_first != null, concat(" | Offender IP: ", tmp_offender_ip_first), ""),
        if(tmp_victim_ip_first != null, concat(" | Victim IP: ", tmp_victim_ip_first), ""))

| alter
    xdm.observer.vendor = "ExtraHop",
    xdm.observer.product = "RevealX",
    xdm.event.id = tmp_event_id,
    xdm.event.type = "ALERT",
    xdm.event.original_event_type = tmp_event_type,
    xdm.event.outcome = XDM_CONST.OUTCOME_UNKNOWN,
    xdm.event.duration = tmp_duration_ms,
    xdm.event.description = tmp_description,
    xdm.alert.original_alert_id = tmp_event_id,
    xdm.alert.name = tmp_alert_title,
    xdm.alert.original_threat_name = tmp_alert_title,
    xdm.alert.description = tmp_alert_description,
    xdm.alert.subcategory = tmp_risk_event_name,
    xdm.alert.source_url = tmp_alert_url,
    xdm.alert.category = tmp_category_const,
    xdm.alert.severity = tmp_severity,
    xdm.alert.risks = if(tmp_risk_band != null, arraycreate(tmp_risk_band), null),
    xdm.event.log_level = tmp_log_level,
    xdm.alert.mitre_tactics = tmp_mitre_tactics_const,
    xdm.alert.mitre_techniques = tmp_mitre_techniques_const,
    // Source side -- the offender drives source.*. Empty when zero offenders.
    xdm.source.ipv4 = tmp_offender_ip_first,
    xdm.source.host.ipv4_addresses = tmp_offender_ip_seq,
    xdm.source.host.hostname = tmp_offender_hostname_first,
    xdm.source.host.device_id = tmp_source_device_id,
    xdm.source.user.upn = tmp_offender_username_first,
    xdm.source.user.username = tmp_offender_username_first,
    xdm.source.user.user_type = if(tmp_offender_username_first != null,
        XDM_CONST.USER_TYPE_REGULAR, null),
    xdm.source.user.identity_type = if(tmp_offender_username_first != null,
        XDM_CONST.IDENTITY_TYPE_USER, null),
    xdm.source.is_internal_ip = tmp_source_is_internal,
    // Target side -- victim drives target.* when present; otherwise mirror
    // the offender so single-sided detections still correlate from either side.
    xdm.target.ipv4 = tmp_target_ip_first,
    xdm.target.host.ipv4_addresses = tmp_target_ip_arr,
    xdm.target.host.hostname = tmp_target_hostname_first,
    xdm.target.host.device_id = tmp_target_device_id,
    xdm.target.user.upn = tmp_target_username_first,
    xdm.target.user.username = tmp_target_username_first,
    xdm.target.user.user_type = if(tmp_target_username_first != null,
        XDM_CONST.USER_TYPE_REGULAR, null),
    xdm.target.user.identity_type = if(tmp_target_username_first != null,
        XDM_CONST.IDENTITY_TYPE_USER, null),
    xdm.target.is_internal_ip = tmp_target_is_internal,
    xdm.intermediate.host.device_id = tmp_appliance_id;
```

## Key decisions called out

- Per-scalar projection, not struct binding. Each scalar from the `offender` participant gets its OWN `arraymap(participants -> [], if(...role = "offender", "@element" -> <field>, null))`. You do NOT write `tmp_offender = arrayindex(arrayfilter(... role = "offender"), 0)` and then `tmp_offender -> field` -- that's ERR-017 (struct passthrough), rejected by the Cortex parser.
- Two-stage temp derivation. Stage 2a derives LEAF temps that depend only on stage-1 outputs (the `_*tmp_first` scalars, the `tmp_severity` and `tmp_log_level` bands). Stage 2b derives DEPENDENT temps that consume 2a outputs (the mirroring logic, the device-id fallback chain, the composite description). This respects parser idiom (xi) -- no sibling-temp-in-same-alter reads.
- Banded `tmp_risk_score`, never raw. `tmp_risk_score` is a numeric 0-99 scale. The rule bands to four `xdm.alert.severity` strings AND to four `XDM_CONST.LOG_LEVEL_*` values. Assigning the raw integer to `xdm.alert.severity` would silently break severity-filter queries downstream -- see failure-mode #7 in [failure-modes.md](../failure-modes.md).
- Categorical enum routing for `categories`. `tmp_category_const` walks the `categories` array via `arraymap` + `arrayfilter`, matching each element against case-insensitive regex patterns and emitting the corresponding `XDM_CONST.THREAT_CATEGORY_*`. First non-null wins. Raw text fallback goes to `xdm.alert.subcategory` via `tmp_risk_event_name`.
- MITRE only when the vendor provides it. `mitre_tactics` and `mitre_techniques` are mapped only when the vendor includes explicit TA*/T* IDs. The rule maps each ID to the corresponding `XDM_CONST.MITRE_*` constant -- it does NOT speculate on vendor-text fields.
- Victim-or-mirror target selection. When a `victim` participant exists, `target.*` is driven by the victim. When ZERO victims exist but offenders do, `target.*` mirrors the offender (single-sided detection -- both sides resolve to the same actor so correlation queries find it from either side). When neither role exists, `target.*` stays null.
- `device_id` fallback chain. When a participant has neither an IP nor a hostname (an unresolved object), `to_string(object_id)` goes into `xdm.{source,target}.host.device_id` so the entity is still queryable.
