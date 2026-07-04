// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: ERR-019. On a _gc_raw dataset every underscore temp must
// reach an xdm.* assignment. `_dead` is extracted but never consumed,
// so Cortex rejects it as 'unused field'. `_used` is fine.

[MODEL: dataset=acme_demo_gc_raw]
filter
    _raw_log != null
| alter
    _used = json_extract_scalar(_raw_log, "$.id"),
    _dead = json_extract_scalar(_raw_log, "$.never_used")
| alter
    xdm.observer.vendor = "Acme",
    xdm.observer.product = "Demo",
    xdm.event.type = "ALERT",
    xdm.event.id = _used
;
