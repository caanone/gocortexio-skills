// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixture: ERR-015 to_number() assigned to integer-typed XDM field.

[MODEL: dataset=acme_demo_raw]
filter _raw_log != null
| alter
    tmp_port_str = json_extract_scalar(_raw_log, "$.server_port")
| alter
    xdm.target.port = to_number(tmp_port_str)
;
