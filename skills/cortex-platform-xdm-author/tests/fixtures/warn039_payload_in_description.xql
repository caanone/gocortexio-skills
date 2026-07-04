// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: WARN-039. The entire ingested payload is dumped into the
// issue description instead of a concat() summary, burying every field
// in free text and defeating structured search.

[MODEL: dataset=acme_demo_raw]
filter
    _raw_log != null
| alter
    _id = json_extract_scalar(_raw_log, "$.id")
| alter
    xdm.observer.vendor = "Acme",
    xdm.event.type = "ALERT",
    xdm.event.id = _id,
    xdm.event.description = _raw_log
;
