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
    tmp_pri        = to_integer(to_number(coalesce(arrayindex(regextract(_raw_log, "^.*<(\d{1,3})>[A-Za-z]{3}\s+\d+\s+[\d:]+"), 0), arrayindex(regextract(_raw_log, "^<(\d{1,3})>"), 0)))),
    tmp_host_5424  = arrayindex(regextract(_raw_log, "^<\d{1,3}>\d+\s+\S+\s+(\S+)\s"), 0),
    tmp_host_3164  = arrayindex(regextract(_raw_log, "^.*<\d{1,3}>[A-Za-z]{3}\s+\d+\s+[\d:]+\s+(\S+)\s"), 0)
| alter
    tmp_syslog_host_raw = coalesce(tmp_host_5424, tmp_host_3164)
| alter
    tmp_syslog_host = if(tmp_syslog_host_raw != "-", tmp_syslog_host_raw)
| alter
    tmp_pri_facility = to_integer(divide(tmp_pri, 8))
| alter
    tmp_pri_severity = to_integer(subtract(tmp_pri, multiply(tmp_pri_facility, 8)))
| alter
    tmp_pri_log_level = if(
        tmp_pri_severity <= 2, XDM_CONST.LOG_LEVEL_CRITICAL,
        tmp_pri_severity = 3,  XDM_CONST.LOG_LEVEL_ERROR,
        tmp_pri_severity = 4,  XDM_CONST.LOG_LEVEL_WARNING,
        tmp_pri_severity = 5,  XDM_CONST.LOG_LEVEL_NOTICE,
        tmp_pri_severity != null, XDM_CONST.LOG_LEVEL_INFORMATIONAL),
    tmp_pri_sev_band = if(
        tmp_pri_severity <= 2, "Critical",
        tmp_pri_severity = 3,  "High",
        tmp_pri_severity = 4,  "Medium",
        tmp_pri_severity != null, "Low")
| alter
    xdm.observer.vendor = "Acme",
    xdm.event.type = "ALERT",
    xdm.observer.name = tmp_syslog_host,
    xdm.event.log_level = tmp_pri_log_level,
    xdm.alert.severity = tmp_pri_sev_band,
    xdm.event.id = to_string(tmp_pri_severity)
;
