// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: WARN-038. The target host is named (hostname) and its IP is
// known (ipv4), but the xdm.target.host.ipv4_addresses array companion
// is missing -- host-based correlation cannot pivot on the address.

[MODEL: dataset=acme_ot_ids_raw]
filter
    _raw_log != null
| alter
    tmp_asset = json_extract_scalar(_raw_log, "$.asset"),
    tmp_dst = json_extract_scalar(_raw_log, "$.dst")
| alter
    xdm.observer.vendor = "Acme",
    xdm.event.type = "ALERT",
    xdm.target.ipv4 = tmp_dst,
    xdm.target.host.hostname = tmp_asset
;
