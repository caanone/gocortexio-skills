// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: WARN-035. xdm.source.host.ipv4_addresses is an Array-type
// field but is assigned a scalar temp. The value must be wrapped with
// arraycreate() (or an array-producing function) to match the shape.

[MODEL: dataset=acme_demo_raw]
filter
    _raw_log != null
| alter
    _ip = json_extract_scalar(_raw_log, "$.client_ip")
| alter
    xdm.observer.vendor = "Acme",
    xdm.event.type = "ALERT",
    xdm.source.ipv4 = _ip,
    xdm.source.host.ipv4_addresses = _ip
;
