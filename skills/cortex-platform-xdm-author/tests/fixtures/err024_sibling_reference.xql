// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixture: ERR-024 sibling reference inside a single alter stage.

[MODEL: dataset=acme_demo_raw]
filter _raw_log != null
| alter
    tmp_a = json_extract_scalar(_raw_log, "$.a"),
    tmp_b = concat(tmp_a, "-suffix")
| alter
    xdm.event.description = tmp_b
;
