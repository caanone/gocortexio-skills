// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: WARN-014. XDM_CONST values must never be quoted. A quoted
// constant is read as a string literal and the mapping is dropped.

[MODEL: dataset=acme_demo_raw]
filter
    _raw_log != null
| alter
    tmp_outcome = json_extract_scalar(_raw_log, "$.outcome")
| alter
    xdm.observer.vendor = "Acme",
    xdm.event.type = "ALERT",
    xdm.event.outcome = if(
        tmp_outcome = "ok", "XDM_CONST.OUTCOME_SUCCESS",
        "XDM_CONST.OUTCOME_FAILED")
;
