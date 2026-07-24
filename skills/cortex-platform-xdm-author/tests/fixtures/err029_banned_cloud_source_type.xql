// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixture: ERR-029 assignment to the banned internal-only field
// xdm.source.cloud.source_type (an XCloud asset field, not part of any
// event data model). ERR-029 must fire; ERR-020 must NOT also fire.

[MODEL: dataset=acme_cloud_raw]
filter _raw_log != null
| alter
    tmp_meta_type = json_extract_scalar(_raw_log, "$.metadata.type")
| alter
    xdm.source.cloud.source_type = tmp_meta_type
;
