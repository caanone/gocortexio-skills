// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: ERR-020. The assignment target xdm.alert.invented_field is
// not a real leaf in the XDM schema, so Cortex rejects the assignment.

[MODEL: dataset=acme_demo_raw]
filter
    _raw_log != null
| alter
    _x = json_extract_scalar(_raw_log, "$.x")
| alter
    xdm.observer.vendor = "Acme",
    xdm.event.type = "ALERT",
    xdm.alert.invented_field = _x
;
