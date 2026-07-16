// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixture: ERR-017 bare arraymap(arr, "@element") on a struct array.

[MODEL: dataset=acme_demo_raw]
filter _raw_log != null
| alter
    tmp_participants = participants -> []
| alter
    tmp_passthrough = arraymap(tmp_participants, "@element")
| alter
    xdm.event.description = arraystring(tmp_passthrough, ", ")
;
