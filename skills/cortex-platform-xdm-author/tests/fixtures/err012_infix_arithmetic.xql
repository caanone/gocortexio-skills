// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixture: ERR-012 infix arithmetic in alter.

[MODEL: dataset=acme_demo_raw]
filter _raw_log != null
| alter
    _end_ms = to_number(json_extract_scalar(_raw_log, "$.end")),
    _start_ms = to_number(json_extract_scalar(_raw_log, "$.start"))
| alter
    xdm.event.duration = _end_ms - _start_ms
;
