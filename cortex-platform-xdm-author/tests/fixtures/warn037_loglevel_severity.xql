// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: WARN-037. The vendor severity field carries log-level words.
// The rule wrongly echoes them into xdm.alert.severity ("Warning",
// "Error") instead of banding them. Severity is a band scale, not a
// syslog level.

[MODEL: dataset=acme_demo_raw]
filter
    _raw_log != null
| alter
    _level = json_extract_scalar(_raw_log, "$.level")
| alter
    xdm.observer.vendor = "Acme",
    xdm.event.type = "ALERT",
    xdm.alert.severity = if(
        _level = "warning", "Warning",
        _level = "error", "Error",
        _level != null, _level)
;
