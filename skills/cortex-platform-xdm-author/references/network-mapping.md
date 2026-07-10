<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Network-event mandatory mapping

Network / traffic events feed the XDM network story and network
analytics. The story only forms when a fixed set of XDM fields is
mapped. A mandatory field left unmapped drops the event from the story,
so this reference is the authoritative checklist for any rule that
models a firewall, flow, proxy, IDS/IPS, DNS, or other
traffic-between-endpoints event.

Classification is PER RECORD. A firewall or gateway feed mixes flows
with VPN logins, admin commands and status chatter, so decide the
network tag and the mandatory set on each record from its own
discriminators, not as one constant across the feed. Records that are
not network events take their own treatment, and unrecognised records
take the catch-all rather than a forced network tag. See
[record-classification.md](record-classification.md).

This guidance is host-agnostic and format-agnostic. Extraction differs
per source format (syslog RFC 3164 / RFC 5424, JSON, JSONL, CEF, LEEF,
key=value), but the XDM target fields and their requirement level are
identical in every case. Map them in the MODEL rule after extraction.
On a syslog source, parse the Stage 0 envelope first
([syslog-envelope.md](syslog-envelope.md)); its targets (observer.name,
log_level, severity) do not overlap the network set, so the two layers
compose cleanly.

## Network is the foundational layer

Network is an underlying, foundational log type: most security profiles
sit ON TOP of a network flow rather than beside one. An IDS or IPS
alert, a WAF block, a proxy decision, a DNS-security verdict -- each of
these describes a network connection first and a security judgement
second, so the rule maps the network mandatory set below IN ADDITION to
its primary alert / threat mapping, not instead of it. The same logic
runs upward: an authentication event that carries the full transport
flow (both endpoint addresses, a port, and a protocol -- a VPN login,
an SSH session, a captive-portal sign-in) is ALSO a network connection,
and takes both mandatory sets with the union of the story tags (see the
dual-events section below).

## When this applies (auto-detection, conservative)

Network transport fields (an IP, a port) appear in almost every log, so
a bare source IP is never enough. Treat a sample as a network event only
on a distinctive signal:

- Field names or values carrying traffic vocabulary: `flow`, `firewall`,
  `traffic`, `connection` / `conn`, `session` combined with transport
  fields, `bytes_sent` / `bytes_received`, `packets`.
- Action values from the allow / deny family: `allow`, `allowed`,
  `permit`, `deny`, `denied`, `drop`, `dropped`, `block`, `blocked`,
  `reset`.
- Protocol-name values: `tcp`, `udp`, `icmp`.
- A complete transport 5-tuple: both endpoint addresses, a port, and a
  protocol all present in the same record.

One precision rule: the allow / deny action family is not proof on its
own when the sample is ALSO an authentication event. An AAA gateway
(TACACS+, RADIUS, Cisco ISE) logs PERMIT / DENY as the authentication
outcome, with no transport flow behind it -- so when permit / deny
vocabulary is the only network evidence (no traffic field names, no
transport 5-tuple, no protocol token), the event stays
authentication-only. Any real flow evidence lifts this -- a protocol
token, traffic vocabulary in the field names, or both connection
endpoints quoted as `IP:port` pairs in one record.

`scripts/profile_log.py` reports this signal in a `network` block of the
worksheet so the detection is deterministic. It is independent of the
`authentication` block -- a VPN login carries both signals and gets both
blocks.

When detected, `scripts/scaffold_rule.py` pre-populates the mandatory
set: it pads every field that has an official placeholder, sets
`xdm.event.type` to a network value, and lists the fields that must come
from the raw log as TODOs rather than inventing values.

Enforcement is advisory. `scripts/lint_rule.py` raises WARN-043 (warning
severity, never an error) for each mandatory field that a network rule
leaves unmapped. The linter treats a rule as a network rule only when it
carries a definitive marker: `XDM_CONST.EVENT_TAG_NETWORK` in the
`xdm.event.tags` assignment, or an `xdm.event.type` value containing
`network`. The exit code stays 0; the author decides.

## Mandatory fields (all 20 must be mapped)

Where the log simply does not carry a value, pad with the type-valid
placeholder so the mandatory status is met.

| XDM target | Type | Mapping / placeholder |
| --- | --- | --- |
| `xdm.event.outcome` | enum | Map the vendor action: allow / permit -> `XDM_CONST.OUTCOME_SUCCESS`, deny / drop / block -> `XDM_CONST.OUTCOME_FAILED`. Pad `XDM_CONST.OUTCOME_UNKNOWN`. |
| `xdm.event.type` | string | Resolve to a value that contains `network`; pad the literal `"network"`. |
| `xdm.event.tags` | array | Must include `XDM_CONST.EVENT_TAG_NETWORK` on the network records. Assign per record via one `if()` so non-network records in the same feed get their own tags (or blank). On a dual authentication + network event emit ONE merged `arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION, XDM_CONST.EVENT_TAG_NETWORK)` -- add `EVENT_TAG_VPN` for a VPN tunnel -- never two tags assignments. See [record-classification.md](record-classification.md). |
| `xdm.network.http.http_header.header` | string | The HTTP header name. Map when the source logs headers; otherwise `""`. (The bare `xdm.network.http.http_header` is a container node, not a mappable field -- some data models reject it -- and `xdm.network.http.response_headers` does not exist; map these two leaves.) |
| `xdm.network.http.http_header.value` | string | The HTTP header value. Map when the source logs headers; otherwise `""`. |
| `xdm.network.http.url_category` | enum | Map the vendor category via an `XDM_CONST.URL_CATEGORY_*` if-chain; pad `XDM_CONST.URL_CATEGORY_UNKNOWN`. Closed list in [xdm-const.md](xdm-const.md). |
| `xdm.network.ip_protocol` | enum | Map the protocol via `XDM_CONST.IP_PROTOCOL_*`; pad `XDM_CONST.IP_PROTOCOL_IP` (the neutral network-layer default when the log carries no protocol). |
| `xdm.network.protocol_layers` | array | `arraycreate(...)` over the known layers, highest last (content-pack idiom, e.g. the application protocol). Pure pad `arraycreate("IP")`, consistent with the `IP_PROTOCOL_IP` protocol pad. |
| `xdm.source.host.device_id` | string | Map the stable client device id; otherwise `""`. |
| `xdm.source.ipv4` | string | Map the observed client address; pad `""` only when the source is IPv6-only. |
| `xdm.source.ipv6` | string | Map the observed client address; pad `""` when the source is IPv4-only. |
| `xdm.source.is_internal_ip` | boolean | Derive from the mapped IP via `incidr()` over RFC 1918 (see the worked shape); pure pad `false`. |
| `xdm.source.port` | integer | Map the value; otherwise `to_integer(0)`. |
| `xdm.source.sent_bytes` | integer | Bytes sent by the source; otherwise `to_integer(0)`. |
| `xdm.target.host.device_id` | string | Map when known; otherwise `""`. |
| `xdm.target.ipv4` | string | Map the observed address; pad `""`. |
| `xdm.target.ipv6` | string | Map the observed address; pad `""`. |
| `xdm.target.is_internal_ip` | boolean | Derive via `incidr()` as for the source; pure pad `false`. |
| `xdm.target.port` | integer | Map the value; otherwise `to_integer(0)`. |
| `xdm.target.sent_bytes` | integer | Bytes sent by the target (bytes received by the source); otherwise `to_integer(0)`. |

Placeholder policy for the mandatory set:

- Numbers (ports, byte counts) -> `to_integer(0)`.
- Strings (device ids, both `http_header` leaves) -> the empty string `""`.
- The IPv4 / IPv6 pair -> map the observed family, pad the other with `""`.
- Booleans -> prefer the `incidr()` derivation; the pure placeholder is
  `false`.
- Enum constants -> a real member of the closed list (`OUTCOME_UNKNOWN`,
  `IP_PROTOCOL_IP`, `URL_CATEGORY_UNKNOWN`) -- never a quoted string.
- Arrays -> `arraycreate(...)` with at least one valid element.
- The event time (generated time) is mapped automatically; do not set it
  manually.

## Deriving the enum fields

Always DERIVE the specific member before falling back to a placeholder.

`xdm.event.outcome` (see the mandatory table): allow / accept / permit
-> `OUTCOME_SUCCESS`; deny / drop / block / reject -> `OUTCOME_FAILED`;
no conclusive action -> `OUTCOME_UNKNOWN`.

`xdm.network.ip_protocol` -- match the vendor protocol token, then fall
back to `IP_PROTOCOL_IP`:

| Protocol value | Member |
| --- | --- |
| tcp, 6 | `XDM_CONST.IP_PROTOCOL_TCP` |
| udp, 17 | `XDM_CONST.IP_PROTOCOL_UDP` |
| icmp, 1 | `XDM_CONST.IP_PROTOCOL_ICMP` |
| (other named protocols) | the matching `XDM_CONST.IP_PROTOCOL_*` |
| absent / unrecognised | `XDM_CONST.IP_PROTOCOL_IP` (neutral default) |

`xdm.network.http.url_category` -- there is no portable value
dictionary: the category vocabulary differs per vendor (PAN-DB,
Zscaler, FortiGuard, Cisco Umbrella each name categories differently).
Map the vendor's category to the closest `XDM_CONST.URL_CATEGORY_*`
member with an `if()` chain keyed on the vendor value (the closed list
is in [xdm-const.md](xdm-const.md)); when the log carries no category,
or the vendor value has no clear XDM equivalent, use
`XDM_CONST.URL_CATEGORY_UNKNOWN`. Do not invent a category.

## Worked shape (JSON source)

A complete MODEL rule that maps all 20 mandatory fields. The extraction
stage changes per format; the assignment stage does not. (On a syslog
source, insert the Stage 0 envelope between the null guard and the
extraction -- see [syslog-envelope.md](syslog-envelope.md).)

```
[MODEL: dataset=vendor_fw_raw]
filter
    _raw_log != null
| alter
    _action = json_extract_scalar(_raw_log, "$.action"),
    _proto = json_extract_scalar(_raw_log, "$.protocol"),
    _src_ip = json_extract_scalar(_raw_log, "$.src_ip"),
    _src_port = json_extract_scalar(_raw_log, "$.src_port"),
    _dst_ip = json_extract_scalar(_raw_log, "$.dst_ip"),
    _dst_port = json_extract_scalar(_raw_log, "$.dst_port"),
    _bytes_out = json_extract_scalar(_raw_log, "$.bytes_sent"),
    _bytes_in = json_extract_scalar(_raw_log, "$.bytes_received")
| alter
    xdm.event.type = "network",
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK),
    xdm.event.outcome = if(
        _action = "allow", XDM_CONST.OUTCOME_SUCCESS,
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
    xdm.source.sent_bytes = to_integer(to_number(_bytes_out)),
    xdm.source.host.device_id = "",
    xdm.target.ipv4 = _dst_ip,
    xdm.target.ipv6 = "",
    xdm.target.is_internal_ip = if(
        incidr(_dst_ip, "10.0.0.0/8"), true,
        incidr(_dst_ip, "172.16.0.0/12"), true,
        incidr(_dst_ip, "192.168.0.0/16"), true,
        false),
    xdm.target.port = to_integer(to_number(_dst_port)),
    xdm.target.sent_bytes = to_integer(to_number(_bytes_in)),
    xdm.target.host.device_id = ""
;
```

## Dual events -- authentication AND network

`xdm.event.tags` is an array, so one event can belong to both stories.
A VPN login is the canonical case: it is a credential validation (the
authentication story) carried over a network session (the network
story), so it also earns `XDM_CONST.EVENT_TAG_VPN`.

Rules for a dual event:

- Emit ONE merged tags assignment:
  `xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION, XDM_CONST.EVENT_TAG_NETWORK)`
  (add `XDM_CONST.EVENT_TAG_VPN` for a VPN tunnel). Two
  `xdm.event.tags` assignments is a defect (the second overwrites the
  first). When the feed also carries records that are neither story,
  make this the branch of a per-record `if()` and let the others fall
  through to their own tags or the blank catch-all
  ([record-classification.md](record-classification.md)).
- Map BOTH mandatory sets. The transport fields (`xdm.source.ipv4`,
  `xdm.target.ipv4`, the ports, `xdm.network.ip_protocol`) appear in
  both sets, so one mapping satisfies both.
- `xdm.event.type` is a single string; use the authentication value
  (the tags array already carries the network marker, and the linter's
  network detection keys on the tag).
- WARN-042 (authentication) and WARN-043 (network) fire independently:
  a dual rule missing fields from both sets receives both advisories.

## Optional fields (map when the source provides them)

| XDM target | Notes |
| --- | --- |
| `xdm.network.dns.dns_question.name` | Queried domain for DNS traffic. |
| `xdm.network.http.url` | Full requested URL. |
| `xdm.network.tls` | TLS summary. The detailed leaves `xdm.network.tls.protocol_version` and `xdm.network.tls.cipher` are also available. |
| `xdm.source.user.username` | Source-side display name. |
| `xdm.target.file.extension` | File transfer: extension. |
| `xdm.target.file.filename` | File transfer: name. |
| `xdm.target.file.md5` | File transfer: MD5. |
| `xdm.target.file.sha256` | File transfer: SHA256. |
| `xdm.target.host.fqdn` | Target host FQDN. |
| `xdm.target.host.hostname` | Target host name. |
| `xdm.target.user.username` | Target-side display name. |

Constants used above live in [xdm-const.md](xdm-const.md); every target
path is defined in [xdm-schema.md](xdm-schema.md).
