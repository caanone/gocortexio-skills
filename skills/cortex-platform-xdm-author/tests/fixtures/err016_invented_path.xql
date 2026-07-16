// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixture: ERR-016 invented xdm.event.start_time / end_time path.

[MODEL: dataset=acme_demo_raw]
filter _raw_log != null
| alter
    tmp_start = json_extract_scalar(_raw_log, "$.start"),
    tmp_end = json_extract_scalar(_raw_log, "$.end")
| alter
    xdm.event.start_time = tmp_start,
    xdm.event.end_time = tmp_end
;
