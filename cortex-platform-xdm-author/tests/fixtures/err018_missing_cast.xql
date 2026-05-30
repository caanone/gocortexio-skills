// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixture: ERR-018 array function called on JSON-string column without
// the '-> []' cast.

[MODEL: dataset=acme_demo_raw]
filter _raw_log != null
| alter
    _joined = arraystring(tags, ", ")
| alter
    xdm.event.description = _joined
;
