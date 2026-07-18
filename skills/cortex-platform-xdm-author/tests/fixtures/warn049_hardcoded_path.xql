// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: WARN-049. The rule derives a "resource type" by hardcoding
// tenant URL path fragments (/keys/, /apps/) into a contains() chain. This
// bakes customer-internal paths into the rule and does not scale, so
// lint_rule.py raises the advisory WARN-049. The fix is to extract the path
// segment dynamically instead.

[MODEL: dataset=acme_apigw_raw]
filter
    _raw_log != null
| alter
    tmp_res_type = if(
        requestUri contains "/keys/", "appkey",
        requestUri contains "/apps/", "app",
        requestUri contains "/developers/", "developer")
| alter
    xdm.observer.vendor = "Acme",
    xdm.event.type = "AUDIT",
    xdm.alert.subcategory = tmp_res_type
;
