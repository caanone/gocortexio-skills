// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
// (SPDX header at the top is for this template file itself; the SPDX
// lines further down belong to the rule the agent emits when it uses
// this template.)
//
// <Vendor> <Product> -- XDM Data Model Rule
// Dataset: <vendor>_<product>_raw
// Vendor: <Vendor> | Product: <Product>
//
// One-paragraph description: explain what this rule does. Standard shape:
// "Maps <Vendor> <Product> <log family> events to the Cortex XDM schema.
// The <product> emits <event count> distinct event types from <single | N
// log shapes>; this rule normalises them into XDM for cross-source
// correlation. <Anchor handshake note if applicable>: the parsing rule
// stamps `_<anchor_name>` columns on every ingested row; this rule
// reads them via `coalesce()` with a regex fallback so historical and
// replayed rows still model identically."
//
// ALERT / EVENT FIELD MAPPING
// ---------------------------
// (Use "ALERT / EVENT FIELD MAPPING" for modelling rules; use "SOURCE
// FIELD MAPPING" for parsing rules. Group related rows with short
// sub-headings: Observer, Event identity, Source, Target, Alert, etc.)
//
// Observer
//   (hardcoded)           -> xdm.observer.vendor
//   (hardcoded)           -> xdm.observer.product
//
// Event identity
//   <vendor_field_1>      -> xdm.event.id, xdm.alert.original_alert_id
//   <vendor_event_type>   -> xdm.event.type (normalised), xdm.event.original_event_type (raw)
//   <vendor_outcome>      -> xdm.event.outcome (XDM_CONST), xdm.observer.action (raw)
//
// Source identity
//   <vendor_src_ip>       -> xdm.source.ipv4
//   <vendor_src_host>     -> xdm.source.host.hostname, xdm.source.host.fqdn
//   <vendor_src_user>     -> xdm.source.user.username, xdm.source.user.upn
//
// Target identity (mirror from source if this is a one-sided detection)
//   <vendor_tgt_ip>       -> xdm.target.ipv4
//   <vendor_tgt_host>     -> xdm.target.host.hostname
//   <vendor_tgt_user>     -> xdm.target.user.username
//
// Alert (if applicable)
//   <vendor_score>        -> xdm.alert.severity (banded), xdm.event.log_level (XDM_CONST.LOG_LEVEL_*)
//   <vendor_category>     -> xdm.alert.category (XDM_CONST.THREAT_CATEGORY_*) or xdm.alert.subcategory (raw)
//   <vendor_name>         -> xdm.alert.name, xdm.alert.original_threat_name
//   <vendor_mitre>        -> xdm.alert.mitre_tactics, xdm.alert.mitre_techniques (when explicit)
//
// Description
//   composed               -> xdm.event.description (concat of identifying fields)
//
// NOT MAPPED
//   <vendor_field_X>      -- <reason, e.g. "no XDM_CONST matches; vendor classification only">
//   <vendor_field_Y>      -- <reason, e.g. "tenant identifier; implicit from dataset">
//   _time                 -- Cortex sets _time automatically in MODEL rules
//   xdm.alert.mitre_techniques -- (only if _gc_raw dataset) WARN-023 blocking on _gc_raw; mitre_tactics only
//
// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later

[MODEL: dataset=<vendor>_<product>_raw]
filter
    _raw_log != null
| alter
    // Stage 1: extract from _raw_log using the relevant pattern (A/B/C/D).
    _<vendor_field_1> = json_extract_scalar(_raw_log, "$.<path_1>"),
    _<vendor_field_2> = json_extract_scalar(_raw_log, "$.<path_2>")
| alter
    // Stage 2: derive composite fields (banded scores, actor projections,
    // categorical enum routing). One alter per logical step keeps sibling
    // refs out of the same stage (parser idiom (xi)).
    _severity = if(
        _<score> >= 80, "Critical",
        _<score> >= 50, "High",
        _<score> >= 30, "Medium",
        _<score> != null, "Low")
| alter
    // Stage 3: assign XDM fields using the extracted temps.
    xdm.observer.vendor = "<Vendor>",
    xdm.observer.product = "<Product>",
    xdm.event.type = "<NORMALISED_CATEGORY>",                  // ALERT/NETWORK/AUTH/EMAIL/FILE/PROCESS/ENDPOINT_ACTIVITY/AUDIT
    xdm.event.original_event_type = _<vendor_event_type>,
    xdm.event.id = _<vendor_field_1>,
    xdm.alert.original_alert_id = _<vendor_field_1>,           // companion pair with xdm.event.id
    xdm.alert.severity = _severity,
    xdm.event.log_level = if(
        _<score> >= 80, XDM_CONST.LOG_LEVEL_CRITICAL,
        _<score> >= 50, XDM_CONST.LOG_LEVEL_ERROR,
        _<score> >= 30, XDM_CONST.LOG_LEVEL_WARNING,
        _<score> != null, XDM_CONST.LOG_LEVEL_INFORMATIONAL)
    // ... additional xdm.* assignments
;
