// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: INFO-013. The single temp _thing is forced across three
// unrelated XDM families (source, target, alert) -- a sign of
// over-mapping one value into fields it does not all belong in.

[MODEL: dataset=acme_demo_raw]
filter
    _raw_log != null
| alter
    _thing = json_extract_scalar(_raw_log, "$.thing")
| alter
    xdm.observer.vendor = "Acme",
    xdm.event.type = "ALERT",
    xdm.source.user.username = _thing,
    xdm.target.user.username = _thing,
    xdm.alert.name = _thing
;
