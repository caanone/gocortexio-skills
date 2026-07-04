// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixture: ERR-014 bareword boolean equality on a string column.

[MODEL: dataset=acme_demo_raw]
filter _raw_log != null
| alter
    _flag = json_extract_scalar(_raw_log, "$.is_active")
| alter
    xdm.event.description = if(json_extract_scalar(_raw_log, "$.is_active") = true, "yes", "no")
;
