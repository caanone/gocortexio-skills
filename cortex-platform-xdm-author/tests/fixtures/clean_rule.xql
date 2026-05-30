// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: a well-formed minimal MODEL rule. lint_rule.py should
// report zero violations.
//
// ALERT / EVENT FIELD MAPPING
//   client_ip   -> xdm.source.ipv4
//   server_port -> xdm.target.port

[MODEL: dataset=acme_demo_raw]
filter
    _raw_log != null
| alter
    _client_ip = json_extract_scalar(_raw_log, "$.client_ip"),
    _server_port_str = json_extract_scalar(_raw_log, "$.server_port"),
    _score = to_number(json_extract_scalar(_raw_log, "$.risk_score"))
| alter
    _severity = if(
        _score >= 80, "Critical",
        _score >= 50, "High",
        _score >= 30, "Medium",
        _score != null, "Low")
| alter
    xdm.observer.vendor = "Acme",
    xdm.observer.product = "Demo",
    xdm.event.type = "ALERT",
    xdm.source.ipv4 = _client_ip,
    xdm.target.port = to_integer(to_number(_server_port_str)),
    xdm.alert.severity = _severity
;
