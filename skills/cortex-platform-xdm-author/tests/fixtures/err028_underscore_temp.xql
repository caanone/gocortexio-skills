// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: a MODEL rule whose scratch temp uses the reserved `_` prefix
// (`_user`) instead of `tmp_`. The `_` namespace is reserved by the
// platform for internal / system-generated fields, so lint_rule.py should
// fire ERR-028. Reading the platform `_raw_log` field is fine and must NOT
// be flagged.

[MODEL: dataset=acme_demo_raw]
filter
    _raw_log != null
| alter
    _user = arrayindex(regextract(_raw_log, "user=([^\s]+)"), 0)
| alter
    xdm.observer.vendor = "Acme",
    xdm.event.type = "ALERT",
    xdm.source.user.username = _user
;
