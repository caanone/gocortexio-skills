// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: the canonical syslog Stage 0 envelope (references/syslog-envelope.md).
// Anchors on the PRI token, never on a vendor literal; decodes the priority
// into facility / severity with function-form arithmetic; and bands the
// severity onto the XDM_CONST log levels. Used by test_syslog_envelope.py to
// prove <134> -> severity 6 (Informational) and <12> -> severity 4 (Warning)
// in the offline verifier, and to prove the idiom lints WARN-040 / WARN-041
// clean.

[MODEL: dataset=demo_raw]
filter
    _raw_log != null
| alter
    _pri        = to_integer(to_number(arrayindex(regextract(_raw_log, "^<(\d{1,3})>"), 0))),
    _host_5424  = arrayindex(regextract(_raw_log, "^<\d{1,3}>\d+\s+\S+\s+(\S+)\s"), 0),
    _host_3164  = arrayindex(regextract(_raw_log, "^<\d{1,3}>[A-Za-z]{3}\s+\d+\s+[\d:]+\s+(\S+)\s"), 0)
| alter
    _syslog_host = coalesce(_host_5424, _host_3164)
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
        _pri_severity != null, XDM_CONST.LOG_LEVEL_INFORMATIONAL),
    _pri_sev_band = if(
        _pri_severity <= 2, "Critical",
        _pri_severity = 3,  "High",
        _pri_severity = 4,  "Medium",
        _pri_severity != null, "Low")
| alter
    xdm.observer.vendor = "Acme",
    xdm.event.type = "ALERT",
    xdm.observer.name = _syslog_host,
    xdm.event.log_level = _pri_log_level,
    xdm.alert.severity = _pri_sev_band,
    xdm.event.id = to_string(_pri_severity)
;
