// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixture: ERR-013 compound null guard inside if().

[MODEL: dataset=acme_demo_raw]
filter _raw_log != null
| alter
    _a = json_extract_scalar(_raw_log, "$.a"),
    _b = json_extract_scalar(_raw_log, "$.b")
| alter
    xdm.event.description = if(_a != null and _b != null, concat(_a, _b), null)
;
