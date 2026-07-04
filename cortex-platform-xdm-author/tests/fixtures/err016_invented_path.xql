// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixture: ERR-016 invented xdm.event.start_time / end_time path.

[MODEL: dataset=acme_demo_raw]
filter _raw_log != null
| alter
    _start = json_extract_scalar(_raw_log, "$.start"),
    _end = json_extract_scalar(_raw_log, "$.end")
| alter
    xdm.event.start_time = _start,
    xdm.event.end_time = _end
;
