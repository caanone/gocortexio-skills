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
    tmp_user = json_extract_scalar(_raw_log, "$.user"),
    tmp_src = json_extract_scalar(_raw_log, "$.src_ip"),
    tmp_result = json_extract_scalar(_raw_log, "$.result")
| alter
    xdm.event.type = "authentication",
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),
    xdm.source.user.upn = if(
        tmp_user contains "@", tmp_user,
        tmp_user != null, concat(tmp_user, "@localhost")),
    xdm.source.ipv4 = tmp_src,
    xdm.event.outcome = if(
        tmp_result = "success", XDM_CONST.OUTCOME_SUCCESS,
        tmp_result != null, XDM_CONST.OUTCOME_FAILED)
;
