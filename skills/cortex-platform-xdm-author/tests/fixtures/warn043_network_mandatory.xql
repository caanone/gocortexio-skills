// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: WARN-043. The rule is marked as a network event (the
// EVENT_TAG_NETWORK story tag) but maps only a fragment of the
// network-story mandatory set: no target side, no ports, no byte
// counts, no protocol, no outcome. Each missing mandatory field must
// surface one advisory WARN-043 finding.

[MODEL: dataset=acmefw_traffic_raw]
filter
    _raw_log != null
| alter
    tmp_src_ip = json_extract_scalar(_raw_log, "$.src_ip")
| alter
    xdm.observer.vendor = "AcmeFW",
    xdm.event.type = "network",
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK),
    xdm.source.ipv4 = tmp_src_ip
;
