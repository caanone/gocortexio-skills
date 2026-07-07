<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Walkthrough 7 -- FortiGate network traffic, one event in two formats, plus a dual story

Vendor / product: Fortinet / FortiGate. Datasets: `fortinet_fortigate_json_raw` (REST log export, native JSON) and `fortinet_fortigate_syslog_raw` (the same events over RFC 3164 syslog).

What this walkthrough shows: the network story is created only when the full mandatory field set from [network-mapping.md](../network-mapping.md) is mapped -- padded with type-valid placeholders where the log has no value -- and that mapping is identical no matter which wire format the event arrives in. The syslog branch composes with the Stage 0 envelope from [syslog-envelope.md](../syslog-envelope.md). A third branch models an SSL-VPN login, which is BOTH an authentication and a network event: `xdm.event.tags` carries the union of the two story markers in one `arraycreate(...)`, and both mandatory sets are mapped. `scripts/profile_log.py` flags each sample deterministically; `scripts/lint_rule.py` raises advisory WARN-043 (and WARN-042 on the dual branch) for anything left unmapped -- warnings only, the exit code stays 0.

## The single canonical event

One allowed outbound web session: client `10.20.30.40:51544` reaches `203.0.113.9:443` over TCP, sends 1220 bytes, receives 8480. Both traffic formats below describe exactly this session, so both rules must produce the same XDM output.

## Format 1 -- native JSON (`fortinet_fortigate_json_raw`)

```json
{
  "eventtime": "1782648001",
  "devid": "FGT60E1234567890",
  "action": "accept",
  "proto": "tcp",
  "srcip": "10.20.30.40",
  "srcport": 51544,
  "dstip": "203.0.113.9",
  "dstport": 443,
  "sentbyte": 1220,
  "rcvdbyte": 8480,
  "catdesc": "Business and Economy",
  "policyname": "outbound-web"
}
```

### Field inventory (JSON)

| JSON path | Type | XDM target |
| --- | --- | --- |
| `$.action` | enum string | `xdm.event.outcome` (accept -> SUCCESS, deny -> FAILED) |
| `$.proto` | string | `xdm.network.ip_protocol`, drives `xdm.network.protocol_layers` |
| `$.srcip` / `$.srcport` | string / int | `xdm.source.ipv4` / `xdm.source.port`; the IP also drives `xdm.source.is_internal_ip` via `incidr()` |
| `$.dstip` / `$.dstport` | string / int | `xdm.target.ipv4` / `xdm.target.port`; drives `xdm.target.is_internal_ip` |
| `$.sentbyte` / `$.rcvdbyte` | int | `xdm.source.sent_bytes` / `xdm.target.sent_bytes` (bytes received by the client are bytes sent by the target) |
| `$.devid` | string | `xdm.source.host.device_id` (the observing appliance's stable id) |
| `$.catdesc` | string | `xdm.network.http.url_category` via the URL_CATEGORY if-chain |

Gaps: FortiGate traffic logs carry no IPv6 pair, no HTTP header, and no target device id. Those mandatory fields take their documented placeholders (`""`) rather than being dropped.

### The full rule (JSON)

```
[MODEL: dataset = fortinet_fortigate_json_raw]
filter
    _raw_log != null
| alter
    _action = json_extract_scalar(_raw_log, "$.action"),
    _proto = json_extract_scalar(_raw_log, "$.proto"),
    _src_ip = json_extract_scalar(_raw_log, "$.srcip"),
    _src_port = json_extract_scalar(_raw_log, "$.srcport"),
    _dst_ip = json_extract_scalar(_raw_log, "$.dstip"),
    _dst_port = json_extract_scalar(_raw_log, "$.dstport"),
    _sent = json_extract_scalar(_raw_log, "$.sentbyte"),
    _rcvd = json_extract_scalar(_raw_log, "$.rcvdbyte"),
    _devid = json_extract_scalar(_raw_log, "$.devid"),
    _catdesc = json_extract_scalar(_raw_log, "$.catdesc")
| alter
    xdm.observer.vendor = "Fortinet",
    xdm.observer.product = "FortiGate",
    xdm.event.type = "network",
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK),
    xdm.event.outcome = if(
        _action = "accept", XDM_CONST.OUTCOME_SUCCESS,
        _action != null, XDM_CONST.OUTCOME_FAILED,
        XDM_CONST.OUTCOME_UNKNOWN),
    xdm.network.ip_protocol = if(
        _proto = "tcp", XDM_CONST.IP_PROTOCOL_TCP,
        _proto = "udp", XDM_CONST.IP_PROTOCOL_UDP,
        _proto = "icmp", XDM_CONST.IP_PROTOCOL_ICMP,
        XDM_CONST.IP_PROTOCOL_IP),
    xdm.network.protocol_layers = if(
        _proto != null, arraycreate(uppercase(_proto)),
        arraycreate("TCP")),
    xdm.network.http.http_header.header = "",
    xdm.network.http.http_header.value = "",
    xdm.network.http.url_category = if(
        _catdesc = "Business and Economy", XDM_CONST.URL_CATEGORY_BUSINESS_AND_ECONOMY,
        _catdesc = "Search Engines", XDM_CONST.URL_CATEGORY_SEARCH_ENGINES,
        XDM_CONST.URL_CATEGORY_UNKNOWN),
    xdm.source.ipv4 = _src_ip,
    xdm.source.ipv6 = "",
    xdm.source.is_internal_ip = if(
        incidr(_src_ip, "10.0.0.0/8"), true,
        incidr(_src_ip, "172.16.0.0/12"), true,
        incidr(_src_ip, "192.168.0.0/16"), true,
        false),
    xdm.source.port = to_integer(to_number(_src_port)),
    xdm.source.sent_bytes = to_integer(to_number(_sent)),
    xdm.source.host.device_id = _devid,
    xdm.target.ipv4 = _dst_ip,
    xdm.target.ipv6 = "",
    xdm.target.is_internal_ip = if(
        incidr(_dst_ip, "10.0.0.0/8"), true,
        incidr(_dst_ip, "172.16.0.0/12"), true,
        incidr(_dst_ip, "192.168.0.0/16"), true,
        false),
    xdm.target.port = to_integer(to_number(_dst_port)),
    xdm.target.sent_bytes = to_integer(to_number(_rcvd)),
    xdm.target.host.device_id = ""
;
```

## Format 2 -- RFC 3164 syslog (`fortinet_fortigate_syslog_raw`)

The same session as a syslog line. Stage 0 parses the envelope first
(PRI-anchored host capture + priority decode, from
[syslog-envelope.md](../syslog-envelope.md)); the key=value payload is
then extracted with Pattern C regextracts. The XDM assignment stage is
the same 20-field block as the JSON rule.

```
<134>Jun 30 12:00:01 fw01 fortigate: action=accept proto=tcp srcip=10.20.30.40 srcport=51544 dstip=203.0.113.9 dstport=443 sentbyte=1220 rcvdbyte=8480 devid=FGT60E1234567890
```

### The full rule (syslog)

```
[MODEL: dataset = fortinet_fortigate_syslog_raw]
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
    _action = arrayindex(regextract(_raw_log, "action=(\w+)"), 0),
    _proto = arrayindex(regextract(_raw_log, "proto=(\w+)"), 0),
    _src_ip = arrayindex(regextract(_raw_log, "srcip=([\d.]+)"), 0),
    _src_port = arrayindex(regextract(_raw_log, "srcport=(\d+)"), 0),
    _dst_ip = arrayindex(regextract(_raw_log, "dstip=([\d.]+)"), 0),
    _dst_port = arrayindex(regextract(_raw_log, "dstport=(\d+)"), 0),
    _sent = arrayindex(regextract(_raw_log, "sentbyte=(\d+)"), 0),
    _rcvd = arrayindex(regextract(_raw_log, "rcvdbyte=(\d+)"), 0),
    _devid = arrayindex(regextract(_raw_log, "devid=(\w+)"), 0)
| alter
    xdm.observer.vendor = "Fortinet",
    xdm.observer.product = "FortiGate",
    xdm.observer.name = _syslog_host,
    xdm.event.log_level = _pri_log_level,
    xdm.event.type = "network",
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK),
    xdm.event.outcome = if(
        _action = "accept", XDM_CONST.OUTCOME_SUCCESS,
        _action != null, XDM_CONST.OUTCOME_FAILED,
        XDM_CONST.OUTCOME_UNKNOWN),
    xdm.network.ip_protocol = if(
        _proto = "tcp", XDM_CONST.IP_PROTOCOL_TCP,
        _proto = "udp", XDM_CONST.IP_PROTOCOL_UDP,
        _proto = "icmp", XDM_CONST.IP_PROTOCOL_ICMP,
        XDM_CONST.IP_PROTOCOL_IP),
    xdm.network.protocol_layers = if(
        _proto != null, arraycreate(uppercase(_proto)),
        arraycreate("TCP")),
    xdm.network.http.http_header.header = "",
    xdm.network.http.http_header.value = "",
    xdm.network.http.url_category = XDM_CONST.URL_CATEGORY_UNKNOWN,
    xdm.source.ipv4 = _src_ip,
    xdm.source.ipv6 = "",
    xdm.source.is_internal_ip = if(
        incidr(_src_ip, "10.0.0.0/8"), true,
        incidr(_src_ip, "172.16.0.0/12"), true,
        incidr(_src_ip, "192.168.0.0/16"), true,
        false),
    xdm.source.port = to_integer(to_number(_src_port)),
    xdm.source.sent_bytes = to_integer(to_number(_sent)),
    xdm.source.host.device_id = _devid,
    xdm.target.ipv4 = _dst_ip,
    xdm.target.ipv6 = "",
    xdm.target.is_internal_ip = if(
        incidr(_dst_ip, "10.0.0.0/8"), true,
        incidr(_dst_ip, "172.16.0.0/12"), true,
        incidr(_dst_ip, "192.168.0.0/16"), true,
        false),
    xdm.target.port = to_integer(to_number(_dst_port)),
    xdm.target.sent_bytes = to_integer(to_number(_rcvd)),
    xdm.target.host.device_id = ""
;
```

Differences versus the JSON rule, all in the transport layer: Stage 0
adds `xdm.observer.name` and the priority-derived `xdm.event.log_level`;
the payload regexes replace `json_extract_scalar`; the basic syslog
traffic line carries no `catdesc`, so `url_category` takes its
placeholder. The 20-field network block itself is unchanged.

## Format 3 -- the dual story: SSL-VPN login (authentication AND network)

A FortiGate SSL-VPN login is one event in BOTH stories: a credential
validation (authentication) carried over a network session (network).
`xdm.event.tags` is an array, so the rule emits the UNION of the two
story markers in a single `arraycreate(...)` -- never two tags
assignments -- and maps both mandatory sets. The overlapping transport
fields (addresses, ports, protocol) are mapped once and satisfy both.
`xdm.event.type` is a single string: the authentication value wins, and
the network story keys on the tag.

```json
{
  "eventtime": "1782648020",
  "devid": "FGT60E1234567890",
  "logdesc": "SSL VPN login",
  "eventtype": "ssl-login",
  "user": "alice@example.com",
  "remip": "198.51.100.23",
  "remport": 51820,
  "tunnelip": "10.212.134.200",
  "result": "success"
}
```

```
[MODEL: dataset = fortinet_fortigate_vpn_raw]
filter
    _raw_log != null
| alter
    _event = json_extract_scalar(_raw_log, "$.eventtype"),
    _user = json_extract_scalar(_raw_log, "$.user"),
    _rem_ip = json_extract_scalar(_raw_log, "$.remip"),
    _rem_port = json_extract_scalar(_raw_log, "$.remport"),
    _devid = json_extract_scalar(_raw_log, "$.devid"),
    _result = json_extract_scalar(_raw_log, "$.result")
| alter
    xdm.observer.vendor = "Fortinet",
    xdm.observer.product = "FortiGate",
    xdm.event.type = "authentication",
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION, XDM_CONST.EVENT_TAG_NETWORK),
    xdm.event.original_event_type = _event,
    xdm.event.operation = XDM_CONST.OPERATION_TYPE_AUTH_LOGIN,
    xdm.event.outcome = if(
        _result = "success", XDM_CONST.OUTCOME_SUCCESS,
        XDM_CONST.OUTCOME_FAILED),
    xdm.auth.service = "IDP",
    xdm.source.user.upn = if(
        _user contains "@", _user,
        _user != null, concat(_user, "@localhost")),
    xdm.source.user.identity_type = if(
        _user != null, XDM_CONST.IDENTITY_TYPE_USER,
        XDM_CONST.IDENTITY_TYPE_UNKNOWN),
    xdm.source.user.user_type = if(
        _user = null, XDM_CONST.USER_TYPE_REGULAR,
        _user contains "$", XDM_CONST.USER_TYPE_MACHINE_ACCOUNT,
        lowercase(_user) ~= "^svc[-_]|service|gserviceaccount",
            XDM_CONST.USER_TYPE_SERVICE_ACCOUNT,
        XDM_CONST.USER_TYPE_REGULAR),
    xdm.network.ip_protocol = XDM_CONST.IP_PROTOCOL_IP,
    xdm.network.protocol_layers = arraycreate("IP"),
    xdm.network.http.http_header.header = "",
    xdm.network.http.http_header.value = "",
    xdm.network.http.url_category = XDM_CONST.URL_CATEGORY_UNKNOWN,
    xdm.source.ipv4 = _rem_ip,
    xdm.source.ipv6 = "",
    xdm.source.is_internal_ip = if(
        incidr(_rem_ip, "10.0.0.0/8"), true,
        incidr(_rem_ip, "172.16.0.0/12"), true,
        incidr(_rem_ip, "192.168.0.0/16"), true,
        false),
    xdm.source.port = to_integer(to_number(_rem_port)),
    xdm.source.sent_bytes = to_integer(0),
    xdm.source.host.device_id = "",
    xdm.target.ipv4 = "",
    xdm.target.ipv6 = "",
    xdm.target.is_internal_ip = true,
    xdm.target.port = to_integer(443),
    xdm.target.sent_bytes = to_integer(0),
    xdm.target.host.device_id = _devid
;
```

Dual-branch decisions worth copying:

- ONE merged tags assignment. A second `xdm.event.tags` would overwrite
  the first and silently drop a story (WARN-043 flags the duplicate).
- `xdm.event.outcome` uses SUCCESS / FAILED only -- the authentication
  story forbids the network padding value OUTCOME_UNKNOWN, and the
  stricter story wins on a dual event.
- The gateway is the validating side, so `xdm.auth.service = "IDP"` and
  the target side carries the appliance: `xdm.target.host.device_id`
  from `devid`, `xdm.target.port` 443 (the SSL-VPN listener),
  `xdm.target.is_internal_ip = true`. The login event logs no byte
  counts, so both `sent_bytes` take `to_integer(0)`.
- The client address comes from `remip` -- the pre-NAT remote peer, the
  best representation of the actual source.
- The SSL-VPN login record carries no protocol field, so
  `xdm.network.ip_protocol` takes the fail-safe `XDM_CONST.IP_PROTOCOL_IP`
  and `xdm.network.protocol_layers` the matching `arraycreate("IP")` --
  the neutral network-layer default, not a guessed transport.

## Checklist

```
[ ] every field in the 20-item network mandatory set assigned in every branch
[ ] placeholders are type-valid: to_integer(0), "", false, OUTCOME_UNKNOWN,
    IP_PROTOCOL_IP, URL_CATEGORY_UNKNOWN, arraycreate("IP")
[ ] is_internal_ip derived via incidr() when the IP is mapped
[ ] syslog branch parses the Stage 0 envelope first (PRI-anchored, never
    a vendor literal)
[ ] dual branch: ONE merged xdm.event.tags arraycreate; event.type keeps
    the authentication value; outcome is SUCCESS / FAILED only
[ ] lint clean: no WARN-042, no WARN-043, exit 0
```
