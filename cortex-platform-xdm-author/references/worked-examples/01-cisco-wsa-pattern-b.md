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

Two-stage extraction: strip the syslog envelope with `regextract`, then `split(..., " ")` and `arrayindex(_parts, N)` for positional fields. The `to_string()` cast around `arrayindex` outputs is mandatory before passing to a downstream `split` or `regextract` -- without it the parser raises a generic error.

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

- `_wsa_http_method` -- HTTP method at position 5, constrained by a closed-vocab regex.
- `_wsa_decision` -- W3C ACL decision tag, the first hyphen-component of the policy decision string.

The MODEL rule must NOT read either column. Cortex validates a MODEL rule statically against the dataset schema, where parser-only `_` columns do not exist, so a bare reference is rejected as "unknown field `_x`" before any `coalesce()` fallback can run (ERR-027). The rule instead derives both values from the raw positional split on its own. You'll see this in stages 2 and 3.5 of the rule below.

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
    _wsa_log = arrayindex(regextract(_raw_log, "Info:\s+(.+)$"), 0),
    _syslog_fqdn = arrayindex(regextract(_raw_log, ">\w+\s+\d+\s+[\d:]+\s+(\S+)\s+accesslogs"), 0)

// -- Stage 2: Split positional fields from the WSA log ----------------------
| alter
    _parts = split(_wsa_log, " ")
| alter
    _elapsed_ms = arrayindex(_parts, 1),
    _client_ip = arrayindex(_parts, 2),
    _result_status = arrayindex(_parts, 3),
    _sc_bytes = arrayindex(_parts, 4),
    // `_http_method` is derived in full from the position-5 split. It is
    // NOT lifted from a parser-stamped `_wsa_http_method` anchor: Cortex
    // validates MODEL rules statically against the dataset schema, where
    // parser-only `_` columns are absent, so reading one is rejected as an
    // unknown field before any coalesce() fallback runs (ERR-027).
    _http_method = arrayindex(_parts, 5),
    _url = arrayindex(_parts, 6),
    _user_raw = arrayindex(_parts, 7),
    _hierarchy_raw = arrayindex(_parts, 8),
    _mime_type = arrayindex(_parts, 9)

// -- Stage 3: Decompose composite fields ------------------------------------
| alter
    _cache_result = arrayindex(split(to_string(_result_status), "/"), 0),
    _http_status_str = arrayindex(split(to_string(_result_status), "/"), 1),
    _peer_host = arrayindex(split(to_string(_hierarchy_raw), "/"), 1),
    _user_username = if(
        _user_raw != "-" and _user_raw != null,
        arrayindex(regextract(to_string(_user_raw), "\\\\([^\"]+)"), 0),
        null),
    _user_domain = if(
        _user_raw != "-" and _user_raw != null,
        arrayindex(regextract(to_string(_user_raw), "\"?([^\\\\\"]+)\\\\"), 0),
        null),
    _url_host = coalesce(
        arrayindex(regextract(to_string(_url), "://([^:/]+)"), 0),
        arrayindex(regextract(to_string(_url), "^([^:/]+)"), 0)),
    _url_port_str = coalesce(
        arrayindex(regextract(to_string(_url), "://[^:/]+:(\d+)"), 0),
        arrayindex(regextract(to_string(_url), "^[^:/]+:(\d+)"), 0)),
    _acl_tag = arrayindex(regextract(_wsa_log, "ERR:\d+\s+(\S+)\s"), 0),
    _syslog_short = arrayindex(split(to_string(_syslog_fqdn), "."), 0)

// -- Stage 3.5: Derive the W3C ACL decision tag from raw --------------------
// `wsa_acl_decision` is derived in full from `_acl_tag`. It is NOT lifted
// from a parser-stamped `_wsa_decision` anchor (ERR-027).
| alter
    wsa_acl_decision = arrayindex(split(to_string(_acl_tag), "-"), 0)

// -- Stage 4: Map to XDM fields ---------------------------------------------
| alter
    // Observer -- the WSA appliance that generated this log entry
    xdm.observer.vendor = "Cisco",
    xdm.observer.product = "Secure Web Appliance",
    xdm.observer.name = _syslog_fqdn,

    // Event -- network transaction metadata
    xdm.event.type = "NETWORK",
    xdm.event.description = concat(
        _http_method, " ", _url,
        " | ", _result_status,
        " | Client: ", _client_ip,
        if(_user_username != null, concat(" | User: ", _user_username), ""),
        if(_peer_host != null and _peer_host != "-", concat(" | Upstream: ", _peer_host), "")),
    xdm.event.duration = to_integer(to_number(_elapsed_ms)),
    xdm.event.outcome = if(
        _cache_result = "TCP_MISS" or _cache_result = "TCP_HIT" or _cache_result = "TCP_MEM_HIT" or _cache_result = "TCP_REFRESH_HIT" or _cache_result = "TCP_IMS_HIT" or _cache_result = "TCP_CLIENT_REFRESH_MISS", XDM_CONST.OUTCOME_SUCCESS,
        _cache_result = "TCP_DENIED", XDM_CONST.OUTCOME_FAILED,
        _cache_result = "NONE", XDM_CONST.OUTCOME_FAILED,
        wsa_acl_decision ~= "^BLOCK_", XDM_CONST.OUTCOME_FAILED,
        wsa_acl_decision ~= "^ALLOW_", XDM_CONST.OUTCOME_SUCCESS,
        wsa_acl_decision ~= "^MONITOR", XDM_CONST.OUTCOME_SUCCESS,
        wsa_acl_decision = "REDIRECT", XDM_CONST.OUTCOME_SUCCESS,
        XDM_CONST.OUTCOME_UNKNOWN),
    xdm.event.outcome_reason = _result_status,

    // Source -- the client that made the request through the proxy
    xdm.source.ipv4 = _client_ip,
    xdm.source.user.username = _user_username,
    xdm.source.user.domain = _user_domain,

    // Target -- the upstream destination server
    xdm.target.host.hostname = if(_peer_host != "-" and _peer_host != null, _peer_host, null),
    xdm.target.url = _url,
    xdm.target.port = if(_url_port_str != null, to_integer(to_number(_url_port_str)), null),
    xdm.target.sent_bytes = to_integer(to_number(_sc_bytes)),

    // Network -- HTTP transaction details
    xdm.network.http.method = _http_method,
    xdm.network.http.response_code = _http_status_str,
    xdm.network.http.content_type = if(_mime_type != "-" and _mime_type != null, _mime_type, null),
    xdm.network.http.url = _url,
    xdm.network.http.domain = _url_host,
    xdm.network.rule = _acl_tag,

    // Intermediate -- the proxy appliance (same device as the observer)
    xdm.intermediate.host.hostname = _syslog_short,
    xdm.intermediate.host.fqdn = _syslog_fqdn;
```

## Key decisions called out

- `-` as empty marker. Every Squid-style field uses `-` for "absent". The rule explicitly guards `if(_user_raw != "-" and _user_raw != null, ...)` before mapping. A naive map would put the string `"-"` into `xdm.source.user.username` and downstream queries would match on it.
- `to_string()` wrap before `split`/`regextract`. Every `arrayindex` output is wrapped before being passed to a downstream string function. Missing the cast produces a generic parser error with no useful line number -- see ERR-018 in [parser-idioms.md](../parser-idioms.md).
- Cache-result + W3C-decision two-tier outcome. `xdm.event.outcome` first tries to match the cache-result token (`TCP_MISS`, `TCP_DENIED`, etc.); if that doesn't match, it falls back to the W3C ACL decision prefix (`BLOCK_*`, `ALLOW_*`, `MONITOR*`). This is defence-in-depth for the unfamiliar-token case.
- `xdm.intermediate.*` for the proxy. The WSA appliance is BOTH the observer AND the network intermediate (it sits between source client and target server). Both are mapped from `_syslog_fqdn` / `_syslog_short`.
- NOT MAPPED (implicit -- would go in the MAPPED-header block of a fresh rule): the rest of the ACL tag's seven hyphen-components beyond the decision prefix; the AVC/AMW verdict columns; the W3C free-form audit columns inside `<...>`. They're vendor-specific and have no XDM home.
