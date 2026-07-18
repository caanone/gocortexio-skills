<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Walkthrough 1 -- Cisco WSA (Pattern B, syslog/positional)

Vendor / product / dataset: Cisco / Secure Web Appliance (WSA) / `cisco_websecurityappliance_raw`.

What the rule does: maps each WSA forward-proxy access-log entry (one HTTP transaction) to the XDM schema. Each row records the proxy's caching decision, scanning verdict, and policy decision for a single client request.

## Synthesised raw log sample

WSA emits Squid-style positional text wrapped in an RFC 3164 syslog header. The body starts with an epoch timestamp at position 0 and runs ~25 space-delimited fields.

```
<142>Apr 15 10:32:18 wsa01.acme.local accesslogs: Info: 1744720338.142 87 10.0.10.42 TCP_MISS/200 14523 GET http://updates.example.com/firmware.bin "ACME\\alice" DIRECT/198.51.100.10 application/octet-stream - ALLOW_WBRS-DefaultGroup-DefaultGroup-NONE-NONE-NONE-DefaultGroup-NONE <"IW_comp",-,-,"-",-,-,-,-,"-","-",-,-,"-","-",-,-,"-","-","-","-",-,-,"IW_comp",-,"-","-","-","-",-,"-",-,"-","-",-,-,-> -
<142>Apr 15 10:32:19 wsa01.acme.local accesslogs: Info: 1744720339.881 4 10.0.10.42 TCP_DENIED/403 0 GET http://malware-c2.example.com/beacon "ACME\\alice" NONE/- - - BLOCK_AMW_RESP-DefaultGroup-DefaultGroup-NONE-NONE-NONE-DefaultGroup-NONE <"IW_mlw",-,4.6,"-",-,-,-,-,"-","-",-,-,"-","-",-,-,"-","-","-","-",-,-,"IW_mlw",-,"-","-","-","-",-,"-",-,"-","-",-,-,-> -
<142>Apr 15 10:32:20 wsa01.acme.local accesslogs: Info: 1744720340.005 12 10.0.10.99 TCP_MISS/407 0 CONNECT proxy.example.com:443 - DIRECT/- - - DEFAULT_CASE-DefaultGroup-DefaultGroup-NONE-NONE-NONE-DefaultGroup-NONE <-,-,-,"-",-,-,-,-,"-","-",-,-,"-","-",-,-,"-","-","-","-",-,-,"-",-,"-","-","-","-",-,"-",-,"-","-",-,-,-> -
```

Note the syslog hostname `wsa01.acme.local` (acme.local marks synthesised data). The empty-field placeholder is `-`. The user field encodes domain and username separated by `\\`.

## Field inventory

Positional indices after `Info: ` (zero-indexed, space-delimited):

| Position | Field | Type | Example |
| --- | --- | --- | --- |
| 0 | epoch timestamp (s.fff) | float | `1744720338.142` |
| 1 | elapsed time (ms) | integer | `87` |
| 2 | client IP | IPv4 string | `10.0.10.42` |
| 3 | result/status (`cache_result/http_status`) | string | `TCP_MISS/200` |
| 4 | bytes sent to client | integer | `14523` |
| 5 | HTTP method | enum string | `GET` |
| 6 | URL | string | `http://updates.example.com/...` |
| 7 | user (`"DOMAIN\\user"` or `-`) | string | `"ACME\\alice"` |
| 8 | hierarchy/peer (`code/host`) | string | `DIRECT/198.51.100.10` |
| 9 | MIME content-type | string | `application/octet-stream` |
| 12 (in ACL tag) | policy decision string | hyphenated | `ALLOW_WBRS-...` |

## Pattern selection

`_raw_log` is a single space-delimited text string wrapped in a syslog header. Per the decision tree in [extraction-patterns.md](../extraction-patterns.md): `_raw_log` contains syslog/text -> Pattern B.

Two-stage extraction: strip the syslog envelope with `regextract`, then `split(..., " ")` and `arrayindex(tmp_parts, N)` for positional fields. The `to_string()` cast around `arrayindex` outputs is mandatory before passing to a downstream `split` or `regextract` -- without it the parser raises a generic error.

## Field-anchor lookups

`scripts/lookup_anchor.py` returns ranked candidates for the extracted positional names. The top hits:

```sh
$ python3 scripts/lookup_anchor.py client_ip
  -> xdm.source.ipv4 (score=1102, freq=192)

$ python3 scripts/lookup_anchor.py elapsed_ms
  -> no candidates (vendor-specific name; map via xdm.event.duration)

$ python3 scripts/lookup_anchor.py http_method
  -> xdm.network.http.method (score=240, freq=24)

$ python3 scripts/lookup_anchor.py url
  -> xdm.target.url (score=2304, freq=48)

$ python3 scripts/lookup_anchor.py sc_bytes
  -> xdm.target.sent_bytes (score=156, freq=12)
```

The synonym index covers the well-known fields. Vendor-specific names (`elapsed_ms`, `acl_tag`) won't match and are mapped by reading the XDM schema directly -- `xdm.event.duration` for elapsed-ms, `xdm.network.rule` for the ACL tag.

## The MODEL derives everything from raw -- it never reads a parser anchor

The WSA parser (`parser.xql` in the pack) stamps two anchor columns at ingest:

- `tmp_wsa_http_method` -- HTTP method at position 5, constrained by a closed-vocab regex.
- `tmp_wsa_decision` -- W3C ACL decision tag, the first hyphen-component of the policy decision string.

The MODEL rule must NOT read either column. Cortex validates a MODEL rule statically against the dataset schema, where parser-only `_` columns do not exist, so a bare reference is rejected as "unknown field `tmp_x`" before any `coalesce()` fallback can run (ERR-027). The rule instead derives both values from the raw positional split on its own. You'll see this in stages 2 and 3.5 of the rule below.

## The full rule

```
// Cisco Web Security Appliance (WSA) -- XDM Data Model Rule
// Dataset: cisco_websecurityappliance_raw
// Vendor: Cisco | Product: Secure Web Appliance
//
// Maps Cisco WSA forward-proxy access log entries (Squid-style,
// space-delimited, syslog-wrapped) to the Cortex XDM schema. Each
// log entry records a single HTTP transaction together with the
// proxy's caching, scanning, and policy decisions.
//
// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later

[MODEL: dataset = cisco_websecurityappliance_raw]

// -- Stage 1: Strip syslog wrapper and extract the WSA log portion ----------
alter
    tmp_wsa_log = arrayindex(regextract(_raw_log, "Info:\s+(.+)$"), 0),
    tmp_syslog_fqdn = arrayindex(regextract(_raw_log, ">\w+\s+\d+\s+[\d:]+\s+(\S+)\s+accesslogs"), 0)

// -- Stage 2: Split positional fields from the WSA log ----------------------
| alter
    tmp_parts = split(tmp_wsa_log, " ")
| alter
    tmp_elapsed_ms = arrayindex(tmp_parts, 1),
    tmp_client_ip = arrayindex(tmp_parts, 2),
    tmp_result_status = arrayindex(tmp_parts, 3),
    tmp_sc_bytes = arrayindex(tmp_parts, 4),
    // `tmp_http_method` is derived in full from the position-5 split. It is
    // NOT lifted from a parser-stamped `tmp_wsa_http_method` anchor: Cortex
    // validates MODEL rules statically against the dataset schema, where
    // parser-only `_` columns are absent, so reading one is rejected as an
    // unknown field before any coalesce() fallback runs (ERR-027).
    tmp_http_method = arrayindex(tmp_parts, 5),
    tmp_url = arrayindex(tmp_parts, 6),
    tmp_user_raw = arrayindex(tmp_parts, 7),
    tmp_hierarchy_raw = arrayindex(tmp_parts, 8),
    tmp_mime_type = arrayindex(tmp_parts, 9)

// -- Stage 3: Decompose composite fields ------------------------------------
| alter
    tmp_cache_result = arrayindex(split(to_string(tmp_result_status), "/"), 0),
    tmp_http_status_str = arrayindex(split(to_string(tmp_result_status), "/"), 1),
    tmp_peer_host = arrayindex(split(to_string(tmp_hierarchy_raw), "/"), 1),
    tmp_user_username = if(
        tmp_user_raw != "-" and tmp_user_raw != null,
        arrayindex(regextract(to_string(tmp_user_raw), "\\\\([^\"]+)"), 0),
        null),
    tmp_user_domain = if(
        tmp_user_raw != "-" and tmp_user_raw != null,
        arrayindex(regextract(to_string(tmp_user_raw), "\"?([^\\\\\"]+)\\\\"), 0),
        null),
    tmp_url_host = coalesce(
        arrayindex(regextract(to_string(tmp_url), "://([^:/]+)"), 0),
        arrayindex(regextract(to_string(tmp_url), "^([^:/]+)"), 0)),
    tmp_url_port_str = coalesce(
        arrayindex(regextract(to_string(tmp_url), "://[^:/]+:(\d+)"), 0),
        arrayindex(regextract(to_string(tmp_url), "^[^:/]+:(\d+)"), 0)),
    tmp_acl_tag = arrayindex(regextract(tmp_wsa_log, "ERR:\d+\s+(\S+)\s"), 0),
    tmp_syslog_short = arrayindex(split(to_string(tmp_syslog_fqdn), "."), 0)

// -- Stage 3.5: Derive the W3C ACL decision tag + cast the status ----------
// `wsa_acl_decision` is derived in full from `tmp_acl_tag`. It is NOT lifted
// from a parser-stamped `tmp_wsa_decision` anchor (ERR-027). `tmp_http_status`
// casts the status string to an integer in a stage AFTER tmp_http_status_str
// is defined (a same-stage sibling reference would be ERR-024).
| alter
    wsa_acl_decision = arrayindex(split(to_string(tmp_acl_tag), "-"), 0),
    tmp_http_status = to_integer(to_number(tmp_http_status_str))

// -- Stage 4: Map to XDM fields ---------------------------------------------
| alter
    // Observer -- the WSA appliance that generated this log entry
    xdm.observer.vendor = "Cisco",
    xdm.observer.product = "Secure Web Appliance",
    xdm.observer.name = tmp_syslog_fqdn,

    // Event -- network transaction metadata
    xdm.event.type = "NETWORK",
    xdm.event.description = concat(
        tmp_http_method, " ", tmp_url,
        " | ", tmp_result_status,
        " | Client: ", tmp_client_ip,
        if(tmp_user_username != null, concat(" | User: ", tmp_user_username), ""),
        if(tmp_peer_host != null and tmp_peer_host != "-", concat(" | Upstream: ", tmp_peer_host), "")),
    xdm.event.duration = to_integer(to_number(tmp_elapsed_ms)),
    xdm.event.outcome = if(
        tmp_cache_result = "TCP_MISS" or tmp_cache_result = "TCP_HIT" or tmp_cache_result = "TCP_MEM_HIT" or tmp_cache_result = "TCP_REFRESH_HIT" or tmp_cache_result = "TCP_IMS_HIT" or tmp_cache_result = "TCP_CLIENT_REFRESH_MISS", XDM_CONST.OUTCOME_SUCCESS,
        tmp_cache_result = "TCP_DENIED", XDM_CONST.OUTCOME_FAILED,
        tmp_cache_result = "NONE", XDM_CONST.OUTCOME_FAILED,
        wsa_acl_decision ~= "^BLOCK_", XDM_CONST.OUTCOME_FAILED,
        wsa_acl_decision ~= "^ALLOW_", XDM_CONST.OUTCOME_SUCCESS,
        wsa_acl_decision ~= "^MONITOR", XDM_CONST.OUTCOME_SUCCESS,
        wsa_acl_decision = "REDIRECT", XDM_CONST.OUTCOME_SUCCESS,
        XDM_CONST.OUTCOME_UNKNOWN),
    xdm.event.outcome_reason = tmp_result_status,

    // Source -- the client that made the request through the proxy
    xdm.source.ipv4 = tmp_client_ip,
    xdm.source.user.username = tmp_user_username,
    xdm.source.user.domain = tmp_user_domain,

    // Target -- the upstream destination server
    xdm.target.host.hostname = if(tmp_peer_host != "-" and tmp_peer_host != null, tmp_peer_host, null),
    xdm.target.url = tmp_url,
    xdm.target.port = if(tmp_url_port_str != null, to_integer(to_number(tmp_url_port_str)), null),
    xdm.target.sent_bytes = to_integer(to_number(tmp_sc_bytes)),

    // Network -- HTTP transaction details
    xdm.network.http.method = tmp_http_method,
    // response_code is const-typed over the FULL HTTP status set. The chain
    // below is the complete crosswalk rendered with
    // `python3 scripts/http_status_map.py --render --temp tmp_http_status`,
    // never a hand-listed subset (a proxy sees every code in production).
    xdm.network.http.response_code = if(
        tmp_http_status = 100, XDM_CONST.HTTP_RSP_CODE_CONTINUE,
        tmp_http_status = 101, XDM_CONST.HTTP_RSP_CODE_SWITCHING_PROTOCOLS,
        tmp_http_status = 102, XDM_CONST.HTTP_RSP_CODE_PROCESSING,
        tmp_http_status = 103, XDM_CONST.HTTP_RSP_CODE_EARLY_HINTS,
        tmp_http_status = 200, XDM_CONST.HTTP_RSP_CODE_OK,
        tmp_http_status = 201, XDM_CONST.HTTP_RSP_CODE_CREATED,
        tmp_http_status = 202, XDM_CONST.HTTP_RSP_CODE_ACCEPTED,
        tmp_http_status = 203, XDM_CONST.HTTP_RSP_CODE_NON__AUTHORITATIVE_INFORMATION,
        tmp_http_status = 204, XDM_CONST.HTTP_RSP_CODE_NO_CONTENT,
        tmp_http_status = 205, XDM_CONST.HTTP_RSP_CODE_RESET_CONTENT,
        tmp_http_status = 206, XDM_CONST.HTTP_RSP_CODE_PARTIAL_CONTENT,
        tmp_http_status = 207, XDM_CONST.HTTP_RSP_CODE_MULTI__STATUS,
        tmp_http_status = 208, XDM_CONST.HTTP_RSP_CODE_ALREADY_REPORTED,
        tmp_http_status = 226, XDM_CONST.HTTP_RSP_CODE_IM_USED,
        tmp_http_status = 300, XDM_CONST.HTTP_RSP_CODE_MULTIPLE_CHOICES,
        tmp_http_status = 301, XDM_CONST.HTTP_RSP_CODE_MOVED_PERMANENTLY,
        tmp_http_status = 302, XDM_CONST.HTTP_RSP_CODE_FOUND,
        tmp_http_status = 303, XDM_CONST.HTTP_RSP_CODE_SEE_OTHER,
        tmp_http_status = 304, XDM_CONST.HTTP_RSP_CODE_NOT_MODIFIED,
        tmp_http_status = 305, XDM_CONST.HTTP_RSP_CODE_USE_PROXY,
        tmp_http_status = 307, XDM_CONST.HTTP_RSP_CODE_TEMPORARY_REDIRECT,
        tmp_http_status = 308, XDM_CONST.HTTP_RSP_CODE_PERMANENT_REDIRECT,
        tmp_http_status = 400, XDM_CONST.HTTP_RSP_CODE_BAD_REQUEST,
        tmp_http_status = 401, XDM_CONST.HTTP_RSP_CODE_UNAUTHORIZED,
        tmp_http_status = 402, XDM_CONST.HTTP_RSP_CODE_PAYMENT_REQUIRED,
        tmp_http_status = 403, XDM_CONST.HTTP_RSP_CODE_FORBIDDEN,
        tmp_http_status = 404, XDM_CONST.HTTP_RSP_CODE_NOT_FOUND,
        tmp_http_status = 405, XDM_CONST.HTTP_RSP_CODE_METHOD_NOT_ALLOWED,
        tmp_http_status = 406, XDM_CONST.HTTP_RSP_CODE_NOT_ACCEPTABLE,
        tmp_http_status = 407, XDM_CONST.HTTP_RSP_CODE_PROXY_AUTHENTICATION_REQUIRED,
        tmp_http_status = 408, XDM_CONST.HTTP_RSP_CODE_REQUEST_TIMEOUT,
        tmp_http_status = 409, XDM_CONST.HTTP_RSP_CODE_CONFLICT,
        tmp_http_status = 410, XDM_CONST.HTTP_RSP_CODE_GONE,
        tmp_http_status = 411, XDM_CONST.HTTP_RSP_CODE_LENGTH_REQUIRED,
        tmp_http_status = 412, XDM_CONST.HTTP_RSP_CODE_PRECONDITION_FAILED,
        tmp_http_status = 413, XDM_CONST.HTTP_RSP_CODE_CONTENT_TOO_LARGE,
        tmp_http_status = 414, XDM_CONST.HTTP_RSP_CODE_URI_TOO_LONG,
        tmp_http_status = 415, XDM_CONST.HTTP_RSP_CODE_UNSUPPORTED_MEDIA_TYPE,
        tmp_http_status = 416, XDM_CONST.HTTP_RSP_CODE_RANGE_NOT_SATISFIABLE,
        tmp_http_status = 417, XDM_CONST.HTTP_RSP_CODE_EXPECTATION_FAILED,
        tmp_http_status = 421, XDM_CONST.HTTP_RSP_CODE_MISDIRECTED_REQUEST,
        tmp_http_status = 422, XDM_CONST.HTTP_RSP_CODE_UNPROCESSABLE_CONTENT,
        tmp_http_status = 423, XDM_CONST.HTTP_RSP_CODE_LOCKED,
        tmp_http_status = 424, XDM_CONST.HTTP_RSP_CODE_FAILED_DEPENDENCY,
        tmp_http_status = 425, XDM_CONST.HTTP_RSP_CODE_TOO_EARLY,
        tmp_http_status = 426, XDM_CONST.HTTP_RSP_CODE_UPGRADE_REQUIRED,
        tmp_http_status = 428, XDM_CONST.HTTP_RSP_CODE_PRECONDITION_REQUIRED,
        tmp_http_status = 429, XDM_CONST.HTTP_RSP_CODE_TOO_MANY_REQUESTS,
        tmp_http_status = 431, XDM_CONST.HTTP_RSP_CODE_REQUEST_HEADER_FIELDS_TOO_LARGE,
        tmp_http_status = 451, XDM_CONST.HTTP_RSP_CODE_UNAVAILABLE_FOR_LEGAL_REASONS,
        tmp_http_status = 500, XDM_CONST.HTTP_RSP_CODE_INTERNAL_SERVER_ERROR,
        tmp_http_status = 501, XDM_CONST.HTTP_RSP_CODE_NOT_IMPLEMENTED,
        tmp_http_status = 502, XDM_CONST.HTTP_RSP_CODE_BAD_GATEWAY,
        tmp_http_status = 503, XDM_CONST.HTTP_RSP_CODE_SERVICE_UNAVAILABLE,
        tmp_http_status = 504, XDM_CONST.HTTP_RSP_CODE_GATEWAY_TIMEOUT,
        tmp_http_status = 505, XDM_CONST.HTTP_RSP_CODE_HTTP_VERSION_NOT_SUPPORTED,
        tmp_http_status = 506, XDM_CONST.HTTP_RSP_CODE_VARIANT_ALSO_NEGOTIATES,
        tmp_http_status = 507, XDM_CONST.HTTP_RSP_CODE_INSUFFICIENT_STORAGE,
        tmp_http_status = 508, XDM_CONST.HTTP_RSP_CODE_LOOP_DETECTED,
        tmp_http_status = 511, XDM_CONST.HTTP_RSP_CODE_NETWORK_AUTHENTICATION_REQUIRED),
    xdm.network.http.content_type = if(tmp_mime_type != "-" and tmp_mime_type != null, tmp_mime_type, null),
    xdm.network.http.url = tmp_url,
    xdm.network.http.domain = tmp_url_host,
    xdm.network.rule = tmp_acl_tag,

    // Intermediate -- the proxy appliance (same device as the observer)
    xdm.intermediate.host.hostname = tmp_syslog_short,
    xdm.intermediate.host.fqdn = tmp_syslog_fqdn;
```

## Key decisions called out

- `-` as empty marker. Every Squid-style field uses `-` for "absent". The rule explicitly guards `if(tmp_user_raw != "-" and tmp_user_raw != null, ...)` before mapping. A naive map would put the string `"-"` into `xdm.source.user.username` and downstream queries would match on it.
- `to_string()` wrap before `split`/`regextract`. Every `arrayindex` output is wrapped before being passed to a downstream string function. Missing the cast produces a generic parser error with no useful line number -- see ERR-018 in [parser-idioms.md](../parser-idioms.md).
- Cache-result + W3C-decision two-tier outcome. `xdm.event.outcome` first tries to match the cache-result token (`TCP_MISS`, `TCP_DENIED`, etc.); if that doesn't match, it falls back to the W3C ACL decision prefix (`BLOCK_*`, `ALLOW_*`, `MONITOR*`). This is defence-in-depth for the unfamiliar-token case.
- Complete HTTP response-code map. `xdm.network.http.response_code` is const-typed over the full status set, so the rule casts the status string to an integer (`tmp_http_status`) and maps EVERY code via the crosswalk chain rendered by `scripts/http_status_map.py`, not just the codes this sample happened to show. A proxy sees the full range in production; a partial hand-written chain silently drops the rest (WARN-048). Never assign the raw status string straight to the const field.
- `xdm.intermediate.*` for the proxy. The WSA appliance is BOTH the observer AND the network intermediate (it sits between source client and target server). Both are mapped from `tmp_syslog_fqdn` / `tmp_syslog_short`.
- NOT MAPPED (implicit -- would go in the MAPPED-header block of a fresh rule): the rest of the ACL tag's seven hyphen-components beyond the decision prefix; the AVC/AMW verdict columns; the W3C free-form audit columns inside `<...>`. They're vendor-specific and have no XDM home.
