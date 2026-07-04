// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: an authentication event (auto-detected via the
// EVENT_TAG_AUTHENTICATION tag) that omits several mandatory
// authentication-story fields. lint_rule.py should raise WARN-042 for
// each missing mandatory field. Advisory only -- the exit code stays 0.
//
// ALERT / EVENT FIELD MAPPING
//   user   -> xdm.source.user.upn
//   src_ip -> xdm.source.ipv4

[MODEL: dataset=acme_idp_raw]
filter
    _raw_log != null
| alter
    _user = json_extract_scalar(_raw_log, "$.user"),
    _src = json_extract_scalar(_raw_log, "$.src_ip"),
    _result = json_extract_scalar(_raw_log, "$.result")
| alter
    xdm.event.type = "authentication",
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),
    xdm.source.user.upn = if(
        _user contains "@", _user,
        _user != null, concat(_user, "@localhost")),
    xdm.source.ipv4 = _src,
    xdm.event.outcome = if(
        _result = "success", XDM_CONST.OUTCOME_SUCCESS,
        _result != null, XDM_CONST.OUTCOME_FAILED)
;
