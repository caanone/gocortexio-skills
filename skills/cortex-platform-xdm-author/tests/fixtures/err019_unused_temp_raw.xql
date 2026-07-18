// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: ERR-019 on a plain _raw dataset (not _gc_raw). Cortex rejects an
// unused field on EVERY dataset ('Datamodel contains unused fields'), so a
// tmp_ that is extracted but never referenced again is a hard error here
// too. `tmp_dead` is orphaned; `tmp_used` reaches xdm.event.id.

[MODEL: dataset=acme_demo_raw]
filter
    _raw_log != null
| alter
    tmp_used = json_extract_scalar(_raw_log, "$.id"),
    tmp_dead = json_extract_scalar(_raw_log, "$.never_used")
| alter
    xdm.observer.vendor = "Acme",
    xdm.event.type = "ALERT",
    xdm.event.id = tmp_used
;
