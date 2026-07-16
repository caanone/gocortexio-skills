<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Extraction recipes (syslog / text / CEF / LEEF)

Verified starting points for the hardest extraction case: a syslog or
text `_raw_log` where fields are not addressable by a JSON path. For
JSON, use Pattern A (`json_extract_scalar`) -- it is exact and needs no
recipe. These recipes exist to raise confidence in field LOCATION and
give clean, well-formed extraction for the shapes that recur across
vendors.

These are advisory, not mandatory. They do NOT replace judgement: copy
the closest recipe, then adapt the regex and the field names to the
actual sample in front of you. Every recipe below is a complete MODEL
rule that lints clean and is checked end-to-end by
`tests/test_extraction_recipes.py` (the sample line in "Yields" is the
verified input/output), so you start from something known-correct rather
than an invented pattern.

General rules that keep extraction clean:

- `regextract(_raw_log, "...(group)...")` returns the FIRST capture
  group as an array; wrap it in `arrayindex(..., 0)` to get the scalar.
- Anchor the value, not the noise: capture `([^\s]+)` (or a typed shape
  like an IPv4 octet quad) rather than greedy `.*`.
- Coerce numerics: `to_integer(to_number(tmp_port))`; wrap an array leaf in
  `arraycreate(...)`.
- For a `<NNN>` priority syslog envelope, decode the header once with the
  canonical Stage 0 idiom in [syslog-envelope.md](syslog-envelope.md)
  first, then apply a payload recipe below. Do not anchor a header regex
  on a vendor literal (WARN-040).

## Recipe 1 -- key=value pairs (unquoted and quoted)

When: the payload is `key=value` tokens, values either bare or
double-quoted (the most common syslog/kv shape).

```
[MODEL: dataset=vendor_kv_raw]
filter
    _raw_log != null
| alter
    tmp_user = arrayindex(regextract(_raw_log, "\buser=([^\s]+)"), 0),
    tmp_msg = arrayindex(regextract(_raw_log, "msg=\"([^\"]*)\""), 0)
| alter
    xdm.source.user.username = tmp_user,
    xdm.event.description = tmp_msg
;
```

Yields, for `ts=2026-07-09 user=alice.admin action=login msg="Login succeeded"`:
`xdm.source.user.username = "alice.admin"`,
`xdm.event.description = "Login succeeded"`. Use `([^\s]+)` for a bare
value and `"([^"]*)"` for a quoted value that may contain spaces.

## Recipe 2 -- transport tuple (src=IP:port dst=IP:port)

When: a firewall / flow line carries endpoints as `src=`/`dst=` with an
optional `:port` suffix.

```
[MODEL: dataset=vendor_fw_raw]
filter
    _raw_log != null
| alter
    tmp_src_ip = arrayindex(regextract(_raw_log, "src=(\d{1,3}(?:\.\d{1,3}){3})"), 0),
    tmp_src_port = arrayindex(regextract(_raw_log, "src=\d{1,3}(?:\.\d{1,3}){3}:(\d{1,5})"), 0),
    tmp_dst_ip = arrayindex(regextract(_raw_log, "dst=(\d{1,3}(?:\.\d{1,3}){3})"), 0)
| alter
    xdm.source.ipv4 = tmp_src_ip,
    xdm.source.port = to_integer(to_number(tmp_src_port)),
    xdm.target.ipv4 = tmp_dst_ip
;
```

Yields, for `action=accept src=10.0.0.5:51000 dst=93.184.216.34:443 proto=tcp`:
`xdm.source.ipv4 = "10.0.0.5"`, `xdm.source.port = 51000`,
`xdm.target.ipv4 = "93.184.216.34"`. The IP is captured by the octet
quad, so it is well-formed even amid noise.

## Recipe 3 -- CEF header + extension

When: the line is `CEF:0|vendor|product|version|sig|name|severity|ext`.
The header is pipe-delimited; the extension is key=value (use Recipe 1).

```
[MODEL: dataset=vendor_cef_raw]
filter
    _raw_log != null
| alter
    tmp_cef_name = arrayindex(split(_raw_log, "|"), 5),
    tmp_suser = arrayindex(regextract(_raw_log, "suser=([^\s]+)"), 0)
| alter
    xdm.event.original_event_type = tmp_cef_name,
    xdm.source.user.username = tmp_suser
;
```

Yields, for `CEF:0|Acme|Box|1.0|100|User login|5|src=10.0.0.5 suser=alice`:
`xdm.event.original_event_type = "User login"`,
`xdm.source.user.username = "alice"`. Header indices: 1 vendor, 2
product, 3 version, 4 signature id, 5 name, 6 severity; the extension is
index 7 onward.

## Recipe 4 -- LEEF header + extension

When: the line is `LEEF:2.0|vendor|product|version|eventid|<key=value ...>`.
Header is pipe-delimited; the eventid is index 4.

```
[MODEL: dataset=vendor_leef_raw]
filter
    _raw_log != null
| alter
    tmp_leef_evt = arrayindex(split(_raw_log, "|"), 4),
    tmp_usr = arrayindex(regextract(_raw_log, "usrName=([^\s\t]+)"), 0)
| alter
    xdm.event.original_event_type = tmp_leef_evt,
    xdm.source.user.username = tmp_usr
;
```

Yields, for `LEEF:2.0|Acme|Box|1.0|4624|usrName=alice src=10.0.0.5`:
`xdm.event.original_event_type = "4624"`,
`xdm.source.user.username = "alice"`. LEEF extension pairs may be tab- or
space-delimited, so stop the value at `[^\s\t]+`.

## Recipe 5 -- Unix syslog process / host (prepend-tolerant, PRI optional)

When: `Mon DD HH:MM:SS host proc[pid]: message`. The same source can
arrive three ways -- direct with a PRI (`<134>Mon DD ...`), direct with
the PRI stripped by a relay (`Mon DD ...`), or relay-prepended with a
second header in front. The host is captured with a greedy `^.*` prefix
and an optional `(?:<\d{1,3}>)?` PRI, so all three yield the origin
host; the `proc[pid]:` process/pid are token-anchored and so are already
position-independent (see the HARD RULE in syslog-envelope.md).

```
[MODEL: dataset=vendor_nix_raw]
filter
    _raw_log != null
| alter
    tmp_host = arrayindex(regextract(_raw_log, "^.*(?:<\d{1,3}>)?[A-Za-z]{3}\s+\d+\s+[\d:]+\s+(\S+)\s"), 0),
    tmp_proc = arrayindex(regextract(_raw_log, "(\w+)\[\d+\]:"), 0),
    tmp_pid = arrayindex(regextract(_raw_log, "\[(\d+)\]:"), 0)
| alter
    xdm.observer.name = tmp_host,
    xdm.source.process.name = tmp_proc,
    xdm.source.process.pid = to_integer(to_number(tmp_pid))
;
```

Yields, for `Jun 19 09:51:59 host01 sshd[1234]: Accepted password for alice`:
`xdm.observer.name = "host01"`, `xdm.source.process.name = "sshd"`,
`xdm.source.process.pid = 1234`. The `<134>Jun 19 09:51:59 host01 ...` and
relay-prepended `<190>... relay01 <134>Jun 19 09:51:59 host01 ...` forms
yield the identical origin `host01` / `sshd` / `1234`.

## Recipe 6 -- clean scalars from a free-text line

When: the message is prose but contains well-formed tokens (an IP, a MAC,
an email/UPN). Capture the token shape, not its position.

```
[MODEL: dataset=vendor_text_raw]
filter
    _raw_log != null
| alter
    tmp_ip = arrayindex(regextract(_raw_log, "\b(\d{1,3}(?:\.\d{1,3}){3})\b"), 0),
    tmp_mac = arrayindex(regextract(_raw_log, "\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b"), 0),
    tmp_email = arrayindex(regextract(_raw_log, "\b([\w.+-]+@[\w.-]+\.\w+)\b"), 0)
| alter
    xdm.source.ipv4 = tmp_ip,
    xdm.source.host.mac_addresses = arraycreate(tmp_mac),
    xdm.source.user.upn = tmp_email
;
```

Yields, for `Login from 10.0.0.5 (aa:bb:cc:dd:ee:ff) by alice@corp.example.com`:
`xdm.source.ipv4 = "10.0.0.5"`,
`xdm.source.host.mac_addresses = ["aa:bb:cc:dd:ee:ff"]`,
`xdm.source.user.upn = "alice@corp.example.com"`. Token-shape capture is
what makes free-text extraction clean and position-independent.

## Recipe 7 -- structured event token (app-severity-event)

When: a network appliance writes a positional line whose payload carries
a compound event token like `Base <APP>-<SEVERITY>-<event_name> - <msg>`
(the Nokia SR OS `tmnx` security log is the canonical case; other
structured appliance logs share the shape). The event name and severity
sit inside the token, and the principal follows as `User <name>`.

```
[MODEL: dataset=vendor_sros_raw]
filter
    _raw_log != null
| alter
    tmp_sros_event = arrayindex(regextract(_raw_log, "Base \w+-\w+-(\w+)"), 0),
    tmp_sros_user = arrayindex(regextract(_raw_log, "\bUser (\S+)"), 0)
| alter
    xdm.event.original_event_type = tmp_sros_event,
    xdm.source.user.username = tmp_sros_user
;
```

Yields, for `<149>Jun 30 12:00:04 router1 tmnx: 470024 Base SECURITY-MAJOR-cli_user_login - User admin1 login from console`:
`xdm.event.original_event_type = "cli_user_login"`,
`xdm.source.user.username = "admin1"`. The same token also carries the
severity (`Base \w+-(\w+)-` -> `MAJOR`; band it to an
`XDM_CONST.LOG_LEVEL_*` via an if-chain) and `from (\S+)` gives the
origin -- a console / session label or a source IP, so map it to
`xdm.source.ipv4` ONLY when it is an address. Keep `xdm.event.type` the
story value (`"authentication"` for `cli_user_login` / `cli_user_logout`),
never the raw token.

## Recipe 8 -- bracketed [key: value] fields (Cisco IOS-style)

When: a positional line carries `[key: value]` bracketed fields after a
`%FACILITY-SEVERITY-MNEMONIC:` token (the Cisco IOS / IOS-XE Catalyst
`%SEC_LOGIN-*` auth line is the canonical case; many IOS mnemonics use
this bracket shape). Capture the compound mnemonic and each bracketed
value.

```
[MODEL: dataset=vendor_ios_raw]
filter
    _raw_log != null
| alter
    tmp_ios_event = arrayindex(regextract(_raw_log, "%([\w]+-\d-\w+):"), 0),
    tmp_ios_user = arrayindex(regextract(_raw_log, "\[user: ?([^\]]+)\]"), 0),
    tmp_ios_src = arrayindex(regextract(_raw_log, "\[Source: ?(\d{1,3}(?:\.\d{1,3}){3})\]"), 0)
| alter
    xdm.event.original_event_type = tmp_ios_event,
    xdm.source.user.username = tmp_ios_user,
    xdm.source.ipv4 = tmp_ios_src
;
```

Yields, for `<190>Jun 30 12:00:04 sw1 %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin] [Source: 10.0.0.5] [localport: 22] at 12:00:04 UTC`:
`xdm.event.original_event_type = "SEC_LOGIN-5-LOGIN_SUCCESS"`,
`xdm.source.user.username = "admin"`, `xdm.source.ipv4 = "10.0.0.5"`. The
`: ?` in each bracket capture tolerates the spaced and unspaced IOS
variants (`[user: x]` and `[user:x]`); the `%FACILITY-SEV-MNEMONIC`
severity digit also bands to a `XDM_CONST.LOG_LEVEL_*`. Keep
`xdm.event.type = "authentication"` for the `SEC_LOGIN` mnemonics.

## Recipe 9 -- parenthesised comma-delimited key=value (Huawei VRP-style)

When: a positional line ends with a `(Key=Value, Key=Value)` trailer
where values are delimited by commas or the closing paren, after a
`%%<ver><MODULE>/<severity>/<BRIEF>` token (the Huawei VRP AAA / SSH /
SHELL log is the canonical case). Recipe 1's `([^\s]+)` would grab the
trailing comma, so anchor the value on `[^,)]+` instead.

```
[MODEL: dataset=vendor_vrp_raw]
filter
    _raw_log != null
| alter
    tmp_vrp_event = arrayindex(regextract(_raw_log, "%%\d*\w+/\d/(\w+)"), 0),
    tmp_vrp_user = arrayindex(regextract(_raw_log, "UserName=([^,)]+)"), 0),
    tmp_vrp_ip = arrayindex(regextract(_raw_log, "IPAddress=([^,)]+)"), 0)
| alter
    xdm.event.original_event_type = tmp_vrp_event,
    xdm.source.user.username = tmp_vrp_user,
    xdm.source.ipv4 = tmp_vrp_ip
;
```

Yields, for `<190>Jun 30 12:00:04 rtr1 %%01SSH/4/SSH_FAIL(l):Failed to login through SSH. (UserName=admin, IPAddress=10.0.0.5)`:
`xdm.event.original_event_type = "SSH_FAIL"`,
`xdm.source.user.username = "admin"`, `xdm.source.ipv4 = "10.0.0.5"`. The
`[^,)]+` capture stops at the comma or the closing paren, so each value
is clean. Classify per record: a VRP `SHELL/.../CMDRECORD` line is a
command execution (process), while `SSH` / `AAA` login lines are
authentication -- see [record-classification.md](record-classification.md).

## Recipe 10 -- Combined Log Format access line (Apache / Tomcat / Nginx)

When: a web access line in Common / Combined Log Format --
`%h %l %u [%t] "%r" %>s %b "%{Referer}i" "%{User-Agent}i"` -- as emitted
by the Tomcat AccessLogValve and Apache httpd / Nginx. This is a network
(HTTP) event; map the request line and user-agent, and classify it
`network` (add `authentication` only when the app genuinely authenticates,
not merely because the URL path contains "login").

```
[MODEL: dataset=vendor_clf_raw]
filter
    _raw_log != null
| alter
    tmp_clf_ip = arrayindex(regextract(_raw_log, "^(\d{1,3}(?:\.\d{1,3}){3})"), 0),
    tmp_clf_method = arrayindex(regextract(_raw_log, "\"(\w+) \S+ HTTP/\d"), 0),
    tmp_clf_url = arrayindex(regextract(_raw_log, "\"\w+ (\S+) HTTP/\d"), 0),
    tmp_clf_ua = arrayindex(regextract(_raw_log, "\"([^\"]*)\"\s*$"), 0)
| alter
    xdm.source.ipv4 = tmp_clf_ip,
    xdm.network.http.method = tmp_clf_method,
    xdm.network.http.url = tmp_clf_url,
    xdm.source.user_agent = tmp_clf_ua
;
```

Yields, for `10.0.0.5 - alice [30/Jun/2025:12:00:04 +0000] "GET /app/login HTTP/1.1" 200 1234 "https://portal.example.com/" "Mozilla/5.0 (Windows NT 10.0)"`:
`xdm.source.ipv4 = "10.0.0.5"`, `xdm.network.http.method = "GET"`,
`xdm.network.http.url = "/app/login"`,
`xdm.source.user_agent = "Mozilla/5.0 (Windows NT 10.0)"`. The status
(`HTTP/\d\.\d" (\d{3})`) bands to `xdm.event.outcome` (2xx/3xx ->
SUCCESS, 4xx/5xx -> FAILED) and `xdm.network.http.response_code`; the
byte count after it maps to `xdm.target.sent_bytes`; the `%u` field (3rd
token, `-` when absent) is the authenticated user when present.

## Recipe 11 -- prepend-robust syslog (Cisco WLC exemplar)

When: any syslog source that arrives both direct off the box and behind an
intermediate relay that prepends its own `<PRI> ts host tag:` header. This
is the HARD RULE for all syslog (see syslog-envelope.md): capture the
envelope relay-aware (greedy `^.*` prefix -> origin host), and capture
every body field on its own token so it matches with or without the
prefix. A Cisco Wireless LAN Controller line shows both -- direct it is
`*task: Mon DD HH:MM:SS.mmm: %FAC-SEV-MNEMONIC: ... for mobile <mac>`; via
a relay it gains `<PRI>Mon DD HH:MM:SS relay-host wlc:` in front.

```
[MODEL: dataset=cisco_wlc_raw]
filter
    _raw_log != null
| alter
    tmp_wlc_host     = arrayindex(regextract(_raw_log, "^.*<\d{1,3}>[A-Za-z]{3}\s+\d+\s+[\d:]+\s+(\S+)\s"), 0),
    tmp_wlc_mnemonic = arrayindex(regextract(_raw_log, "%(\w+-\d-\w+):"), 0),
    tmp_wlc_mac      = arrayindex(regextract(_raw_log, "for mobile ([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})"), 0)
| alter
    xdm.observer.name = tmp_wlc_host,
    xdm.event.original_event_type = tmp_wlc_mnemonic,
    xdm.source.host.mac_addresses = arraycreate(tmp_wlc_mac)
;
```

Yields, for the relay-prepended
`<134>Jul 14 15:41:24 wlc-mgmt.example.net wlc01: *apfReceiveTask: Jul 14 15:41:24.640: %APF-6-USER_NAME_CREATED: [SS]apf_ms.c:9003 Username entry (3E-A8-8D-20-D1-1E) with length (17) created for mobile 3e:a8:8d:20:d1:1e`:
`xdm.observer.name = "wlc-mgmt.example.net"`,
`xdm.event.original_event_type = "APF-6-USER_NAME_CREATED"`,
`xdm.source.host.mac_addresses = ["3e:a8:8d:20:d1:1e"]`. The direct line
`*apfReceiveTask: Jul 14 15:41:24.640: %APF-6-USER_NAME_CREATED: ... for mobile 3e:a8:8d:20:d1:1e`
yields the identical mnemonic and MAC (host is null off the box, sourced
from a payload field when needed). The `%FAC-SEV-MNEMONIC` token and the
`for mobile <mac>` phrase are the position-independent anchors -- neither
depends on the header being present.

## Choosing the target

A recipe extracts a value cleanly; the field-anchor index
(`scripts/lookup_anchor.py`) tells you which `xdm.*` path it belongs to.
Use them together: recipe for the extraction, anchor lookup for the
location. When a value has no confident XDM home, document it in the
NOT MAPPED block rather than forcing it.
