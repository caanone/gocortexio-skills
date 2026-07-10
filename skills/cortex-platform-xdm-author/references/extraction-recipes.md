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
- Coerce numerics: `to_integer(to_number(_port))`; wrap an array leaf in
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
    _user = arrayindex(regextract(_raw_log, "\buser=([^\s]+)"), 0),
    _msg = arrayindex(regextract(_raw_log, "msg=\"([^\"]*)\""), 0)
| alter
    xdm.source.user.username = _user,
    xdm.event.description = _msg
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
    _src_ip = arrayindex(regextract(_raw_log, "src=(\d{1,3}(?:\.\d{1,3}){3})"), 0),
    _src_port = arrayindex(regextract(_raw_log, "src=\d{1,3}(?:\.\d{1,3}){3}:(\d{1,5})"), 0),
    _dst_ip = arrayindex(regextract(_raw_log, "dst=(\d{1,3}(?:\.\d{1,3}){3})"), 0)
| alter
    xdm.source.ipv4 = _src_ip,
    xdm.source.port = to_integer(to_number(_src_port)),
    xdm.target.ipv4 = _dst_ip
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
    _cef_name = arrayindex(split(_raw_log, "|"), 5),
    _suser = arrayindex(regextract(_raw_log, "suser=([^\s]+)"), 0)
| alter
    xdm.event.original_event_type = _cef_name,
    xdm.source.user.username = _suser
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
    _leef_evt = arrayindex(split(_raw_log, "|"), 4),
    _usr = arrayindex(regextract(_raw_log, "usrName=([^\s\t]+)"), 0)
| alter
    xdm.event.original_event_type = _leef_evt,
    xdm.source.user.username = _usr
;
```

Yields, for `LEEF:2.0|Acme|Box|1.0|4624|usrName=alice src=10.0.0.5`:
`xdm.event.original_event_type = "4624"`,
`xdm.source.user.username = "alice"`. LEEF extension pairs may be tab- or
space-delimited, so stop the value at `[^\s\t]+`.

## Recipe 5 -- relay-stripped RFC 3164 syslog (no PRI)

When: a relay has stripped the `<NNN>` priority, leaving
`Mon DD HH:MM:SS host proc[pid]: message`. (With a PRI present, decode the
envelope via Stage 0 first.)

```
[MODEL: dataset=vendor_nix_raw]
filter
    _raw_log != null
| alter
    _host = arrayindex(regextract(_raw_log, "^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)"), 0),
    _proc = arrayindex(regextract(_raw_log, "(\w+)\[\d+\]:"), 0),
    _pid = arrayindex(regextract(_raw_log, "\[(\d+)\]:"), 0)
| alter
    xdm.observer.name = _host,
    xdm.source.process.name = _proc,
    xdm.source.process.pid = to_integer(to_number(_pid))
;
```

Yields, for `Jun 19 09:51:59 host01 sshd[1234]: Accepted password for alice`:
`xdm.observer.name = "host01"`, `xdm.source.process.name = "sshd"`,
`xdm.source.process.pid = 1234`. The `proc[pid]:` shape is the reliable
anchor for process name and pid on Unix syslog.

## Recipe 6 -- clean scalars from a free-text line

When: the message is prose but contains well-formed tokens (an IP, a MAC,
an email/UPN). Capture the token shape, not its position.

```
[MODEL: dataset=vendor_text_raw]
filter
    _raw_log != null
| alter
    _ip = arrayindex(regextract(_raw_log, "\b(\d{1,3}(?:\.\d{1,3}){3})\b"), 0),
    _mac = arrayindex(regextract(_raw_log, "\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b"), 0),
    _email = arrayindex(regextract(_raw_log, "\b([\w.+-]+@[\w.-]+\.\w+)\b"), 0)
| alter
    xdm.source.ipv4 = _ip,
    xdm.source.host.mac_addresses = arraycreate(_mac),
    xdm.source.user.upn = _email
;
```

Yields, for `Login from 10.0.0.5 (aa:bb:cc:dd:ee:ff) by alice@corp.example.com`:
`xdm.source.ipv4 = "10.0.0.5"`,
`xdm.source.host.mac_addresses = ["aa:bb:cc:dd:ee:ff"]`,
`xdm.source.user.upn = "alice@corp.example.com"`. Token-shape capture is
what makes free-text extraction clean and position-independent.

## Choosing the target

A recipe extracts a value cleanly; the field-anchor index
(`scripts/lookup_anchor.py`) tells you which `xdm.*` path it belongs to.
Use them together: recipe for the extraction, anchor lookup for the
location. When a value has no confident XDM home, document it in the
NOT MAPPED block rather than forcing it.
