// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: a MODEL rule that reads parser-stamped underscore anchors
// instead of deriving the values from raw columns. lint_rule.py should
// fire ERR-027. Two shapes are exercised:
//   tmp_severity = coalesce(tmp_severity, <derivation>)  -- self-reference, so
//       the bare tmp_severity read survives.
//   to_number(tmp_server_port)                        -- a bare anchor read
//       that is never assigned in the rule.
// Cortex validates a MODEL rule statically against the dataset schema,
// where parser-only `_` columns are absent, so each read is rejected as
// an unknown field before any coalesce() fallback can run.

[MODEL: dataset=acme_demo_raw]
filter
    _raw_log != null
| alter
    tmp_client_ip = json_extract_scalar(_raw_log, "$.client_ip"),
    tmp_severity = coalesce(tmp_severity, json_extract_scalar(_raw_log, "$.severity"))
| alter
    xdm.source.ipv4 = tmp_client_ip,
    xdm.alert.severity = tmp_severity,
    xdm.target.port = to_integer(to_number(tmp_server_port))
;
