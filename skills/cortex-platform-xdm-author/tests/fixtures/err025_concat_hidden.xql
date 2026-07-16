// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: ERR-025. On a _gc_raw dataset a temp whose only consumer is
// inside a concat() / arraystring() body is invisible to Cortex's
// unused-field tracer and is rejected as 'unused field'. `tmp_note` is only
// read inside the concat(); `tmp_action` reaches an xdm.* field directly.

[MODEL: dataset=acme_demo_gc_raw]
filter
    _raw_log != null
| alter
    tmp_action = json_extract_scalar(_raw_log, "$.action"),
    tmp_note = json_extract_scalar(_raw_log, "$.note")
| alter
    xdm.observer.vendor = "Acme",
    xdm.observer.product = "Demo",
    xdm.event.type = "ALERT",
    xdm.observer.action = tmp_action,
    xdm.event.description = concat("Note: ", tmp_note)
;
