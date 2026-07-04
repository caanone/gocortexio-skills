<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Syslog envelope parsing -- the transport layer beneath Pattern B

Every syslog source carries two independent layers. The envelope is the
RFC 3164 or RFC 5424 transport wrapper (priority, timestamp, host, tag).
The payload is the vendor body that Pattern B parses. Today rules parse
the payload and hand-roll a one-off header regex anchored on a vendor
literal (for example the trailing tag word). That anchor breaks on the
next source and discards the priority value entirely.

Parse the envelope first, with the one canonical idiom below, then parse
the payload. The envelope idiom is identical across every syslog source,
so it is written once and reused. See [extraction-patterns.md](extraction-patterns.md)
for the payload patterns (A, B, C, D) that run after Stage 0.

## When this applies

Apply this whenever `_raw_log` begins with a syslog priority token
`<NNN>` (RFC 3164 or RFC 5424). `profile_log.py` reports a
`detected_format` of `syslog-3164` or `syslog-5424` for these sources.
If there is no `<NNN>` priority (a relay stripped it), skip the priority
decode; the host then has no fixed position either, so read it from a
payload field instead of the envelope (see "When the priority is
stripped" below).

## The two-layer model

```
Stage 0  envelope   priority, host, app/tag      <- this file, identical everywhere
Stage 1+ payload    vendor key=value / JSON      <- extraction-patterns.md
```

Keep Stage 0 as the first `alter` after the MODEL header (after the
mandatory `filter _raw_log != null` guard). Never assign `_time` in a
MODEL rule (Cortex sets it at INGEST -- see WARN-018); the envelope
timestamp is therefore NOT MAPPED.

## Stage 0 -- canonical envelope capture (RFC 3164 and RFC 5424)

Anchor on the priority token, never on a vendor literal. The host sits
in a different position in each RFC, so capture both and coalesce; the
two patterns are mutually exclusive (5424 has a numeric version after
the priority, 3164 has a month name), so the coalesce is unambiguous.

```
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
```

RFC 5424 permits the NILVALUE `-` for the HOSTNAME field, so the final
guard stage nulls it out: a relay that hides the host can never leak a
literal `-` into `xdm.observer.name` -- the field stays null and the
author sources the observer from a payload field instead.

Optional envelope fields (capture only when you will map them):

```
    _app_5424 = arrayindex(regextract(_raw_log, "^<\d{1,3}>\d+\s+\S+\s+\S+\s+(\S+)\s"), 0),
    _tag_3164 = arrayindex(regextract(_raw_log, "^<\d{1,3}>[A-Za-z]{3}\s+\d+\s+[\d:]+\s+\S+\s+([A-Za-z0-9_\-]+)(?:\[|:)"), 0),
    _sd_param = arrayindex(regextract(_raw_log, "\[[^\]]*\bKEYNAME=\"([^\"]+)\""), 0)
```

Standard envelope assignment:

```
    xdm.observer.name = _syslog_host
```

## Priority decode -- facility and severity (function-form, ERR-012 safe)

The priority encodes two values: `facility = PRI div 8` and
`severity = PRI mod 8`. There is no `modulo()` or `floor()` function and
infix arithmetic is banned (see [parser-idioms.md](parser-idioms.md)
ERR-012), so decode with the documented function-form arithmetic. This
works because `to_integer()` truncates toward zero and PRI is never
negative, so `to_integer(divide(...))` is an exact floor.

Facility and severity sit in two separate `alter` stages: severity reads
the facility temp, and Cortex evaluates every target in a single `alter`
in parallel, so referencing a sibling temp in the same stage is rejected
as an unknown field (the bundled linter flags it as ERR-024). Compute the
facility first, then read it in the next stage.

```
| alter
    _pri_facility = to_integer(divide(_pri, 8))
| alter
    _pri_severity = to_integer(subtract(_pri, multiply(_pri_facility, 8)))
```

Worked check: `<134>` -> `divide(134, 8) = 16.75` -> `to_integer = 16`
(facility 16, local0); `subtract(134, multiply(16, 8)) = 6` (severity 6,
Informational). A rounding-sensitive case to keep in the test suite:
`<12>` -> facility 1, severity 4; if `to_integer` ever rounded instead of
truncating, severity would compute as -4 and the test would catch it.

Map the numeric severity (0-7) onto the constants already shipped
(see [xdm-const.md](xdm-const.md)). XDM has no Debug or Emergency/Alert
level, so floor the ends:

```
| alter
    _pri_log_level = if(
        _pri_severity <= 2, XDM_CONST.LOG_LEVEL_CRITICAL,
        _pri_severity = 3,  XDM_CONST.LOG_LEVEL_ERROR,
        _pri_severity = 4,  XDM_CONST.LOG_LEVEL_WARNING,
        _pri_severity = 5,  XDM_CONST.LOG_LEVEL_NOTICE,
        _pri_severity != null, XDM_CONST.LOG_LEVEL_INFORMATIONAL),
    _pri_sev_band = if(
        _pri_severity <= 2, "Critical",
        _pri_severity = 3,  "High",
        _pri_severity = 4,  "Medium",
        _pri_severity != null, "Low")
```

## Use the decoded priority as a FALLBACK, never an override

The payload almost always carries a richer severity (for example
`sev=68`). The decoded priority is the floor that keeps the field
populated when the payload omits severity. Always prefer the payload:

```
| alter
    xdm.alert.severity  = coalesce(_payload_sev_band, _pri_sev_band),
    xdm.event.log_level = coalesce(_payload_log_level, _pri_log_level)
```

If the payload has its own severity, the priority decode is dropped by
the coalesce -- that is correct. (Both payload temps must be produced
from raw columns earlier in the rule; a coalesce over an undefined
underscore field is rejected by the linter as ERR-027.)

## When the priority is stripped

A relay can forward a record with the `<NNN>` token removed. Then `_pri`
is null and the decode chain yields null all the way through, which the
coalesce above handles: severity and log_level fall to whatever the
payload provides. The host capture also returns null, because it is
anchored on the priority token by design (never on a vendor literal), and
without that anchor there is no fixed host position. Read the host from a
payload field in that case rather than re-anchoring on a vendor word.

## What stays NOT MAPPED

```
NOT MAPPED
  syslog timestamp  -- Cortex sets _time at INGEST; MODEL rules must not assign _time (WARN-018)
  raw PRI integer   -- transport detail; only the decoded facility/severity carry meaning
  facility          -- no XDM home; retain only if a downstream rule needs it, else omit
```

## Determinism notes

- Always emit `xdm.observer.name` from `_syslog_host` on a syslog source.
- Priority decode is a coalesce fallback only; it never overrides payload severity.
- Host capture is anchored on the priority token, never on a vendor literal.
  The linter flags a vendor-anchored header regex as WARN-040.
- If you capture the priority, decode it: a PRI captured but never turned
  into log_level or severity is flagged as WARN-041.
- Facility and severity live in separate alter stages (ERR-024).
- See [transformation-patterns.md](transformation-patterns.md) for the
  companion-pair and String-passthrough rules that apply to the payload.

## Checklist

```
[ ] filter _raw_log != null is the first stage
[ ] PRI captured with ^<(\d{1,3})> (when present)
[ ] host captured via the RFC 3164 + RFC 5424 coalesce, not a vendor literal
[ ] NILVALUE hostname (-) guarded to null, never mapped literally
[ ] priority decoded with function-form arithmetic (no infix, no modulo)
[ ] facility and severity in separate alter stages (no sibling reference)
[ ] severity/log_level use coalesce(payload, priority) -- payload wins
[ ] no _time assignment (WARN-018)
[ ] decode proven with verify_rule.py: <134> -> Informational, <12> -> severity 4
```
