// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixture: ERR-017 bare arraymap(arr, "@element") on a struct array.

[MODEL: dataset=acme_demo_raw]
filter _raw_log != null
| alter
    _participants = participants -> []
| alter
    _passthrough = arraymap(_participants, "@element")
| alter
    xdm.event.description = arraystring(_passthrough, ", ")
;
