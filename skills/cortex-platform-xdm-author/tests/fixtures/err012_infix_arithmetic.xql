// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixture: ERR-012 infix arithmetic in alter.

[MODEL: dataset=acme_demo_raw]
filter _raw_log != null
| alter
    tmp_end_ms = to_number(json_extract_scalar(_raw_log, "$.end")),
    tmp_start_ms = to_number(json_extract_scalar(_raw_log, "$.start"))
| alter
    xdm.event.duration = tmp_end_ms - tmp_start_ms
;
