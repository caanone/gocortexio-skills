// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: WARN-040. The syslog header is parsed with a positional regex
// anchored on the trailing vendor word (CortexGrid) instead of the PRI
// token. That anchor breaks on the next source and discards the priority.

[MODEL: dataset=cortexgrid_raw]
filter
    _raw_log != null
| alter
    _host = arrayindex(regextract(_raw_log, "[A-Za-z]{3}\s+\d+\s+[\d:]+\s+(\S+)\s+CortexGrid"), 0)
| alter
    xdm.observer.vendor = "CortexGrid",
    xdm.event.type = "ALERT",
    xdm.observer.name = _host
;
