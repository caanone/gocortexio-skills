// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: WARN-041. The PRI is anchored and captured (^<(\d{1,3})>) but
// it is only used for the event id; neither xdm.event.log_level nor
// xdm.alert.severity is ever assigned, so the priority severity is lost.

[MODEL: dataset=cortexgrid_raw]
filter
    _raw_log != null
| alter
    _pri  = to_integer(to_number(arrayindex(regextract(_raw_log, "^<(\d{1,3})>"), 0))),
    _host = arrayindex(regextract(_raw_log, "^<\d{1,3}>[A-Za-z]{3}\s+\d+\s+[\d:]+\s+(\S+)\s"), 0)
| alter
    xdm.observer.vendor = "CortexGrid",
    xdm.event.type = "ALERT",
    xdm.observer.name = _host,
    xdm.event.id = to_string(_pri)
;
