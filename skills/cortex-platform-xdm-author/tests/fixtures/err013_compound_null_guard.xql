// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixture: ERR-013 compound null guard inside if().

[MODEL: dataset=acme_demo_raw]
filter _raw_log != null
| alter
    tmp_a = json_extract_scalar(_raw_log, "$.a"),
    tmp_b = json_extract_scalar(_raw_log, "$.b")
| alter
    xdm.event.description = if(tmp_a != null and tmp_b != null, concat(tmp_a, tmp_b), null)
;
