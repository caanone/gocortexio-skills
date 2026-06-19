<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Worked examples -- index

Five production-derived walkthroughs, one per extraction pattern. Each takes a synthesised raw log sample and walks through to a complete, validated `[MODEL: dataset=..._raw]` rule. Load only the walkthrough whose pattern matches the log in front of you.

The final XQL in each walkthrough is a complete, validated rule reproduced verbatim. The vendor name in each header is real because the rules target real log formats; you would use the same `xdm.observer.vendor` string when authoring against those products. The raw log samples are synthesised with fake addresses (`acme.local`, `10.0.0.1`, `alice@example.com`) so no real customer data is reproduced.

## Walkthroughs

| # | File | Vendor / dataset | Pattern | Notes |
| --- | --- | --- | --- | --- |
| 1 | [01-cisco-wsa-pattern-b.md](worked-examples/01-cisco-wsa-pattern-b.md) | Cisco WSA / `cisco_websecurityappliance_raw` | B (syslog-wrapped positional) | Shortest rule (~123 LOC). Start here for a syslog-based pack. |
| 2 | [02-aws-guardduty-nested-json.md](worked-examples/02-aws-guardduty-nested-json.md) | AWS GuardDuty / `amazon_aws_guardduty_raw` | D (nested JSON, cloud-native) | PascalCase/camelCase duals, directional-IP resolution, closed-list `XDM_CONST` mapping. Mid-length (~385 LOC). |
| 3 | [03-extrahop-revealx-pattern-d-prime.md](worked-examples/03-extrahop-revealx-pattern-d-prime.md) | ExtraHop RevealX / `extrahop_revealx_raw` | D' (role-filtered array of objects) | Hardest pattern: `participants[]` projected per-scalar, banded scoring, MITRE constant mapping, `-> []` JSON-string cast. |
| 4 | [04-trend-micro-vision-one-pattern-d.md](worked-examples/04-trend-micro-vision-one-pattern-d.md) | Trend Micro Vision One / `trendmicro_visionone_raw` | D (arrow operator on pre-parsed top-level columns; `_raw_log` is null) | `processChainInfo[0]` JSON re-extraction, `filters[]` projection, self-sufficient derivation of `_source` / `_severity_band` from raw. |
| 5 | [05-imperva-audit-trail-pattern-a.md](worked-examples/05-imperva-audit-trail-pattern-a.md) | Imperva Audit Trail / `imperva_audit_trail_raw` | A (`json_extract_scalar` on a top-level JSON-string column) | Smallest rule (~92 LOC). Pure `json_extract_scalar(to_string(<column>), "$.path")` idiom. |
| 6 | [06-okta-authentication-multi-format.md](worked-examples/06-okta-authentication-multi-format.md) | Okta / Identity Cloud | A (JSON) and B (RFC 5424 syslog) | One authentication event in two wire formats. Mandatory 12-field authentication-story mapping (WARN-042); extraction differs, XDM assignment is identical. |

## Each walkthrough follows the same structure

- Framing -- vendor, product, dataset, what the rule does.
- Synthesised raw log sample -- 3-5 lines of fake-but-faithful data.
- Field inventory -- what's in the sample, what data type, what it means.
- Pattern selection -- which extraction pattern from [extraction-patterns.md](extraction-patterns.md) applies and why.
- Field-anchor lookups -- what `scripts/lookup_anchor.py` returns for the key vendor fields, and what gets selected.
- The full rule -- verbatim from the corresponding pack's `datamodel.xql`.
- Key decisions called out -- banded scoring, companion pairs, NOT MAPPED reasoning, self-sufficient derivation.

## A MODEL rule never reads a parser-stamped anchor

Some packs have a parser (`parser.xql`) that stamps underscore anchor
columns (e.g. `_wsa_http_method`, `_action_type`, `_severity_band`) at
ingest. A MODEL rule must NOT read those columns. Cortex validates a
MODEL rule statically against the dataset schema, where parser-only `_`
anchors do not exist, so a bare reference is rejected as "unknown field
`_x`" BEFORE any `coalesce()` fallback can run. Earlier revisions of
these walkthroughs used a `coalesce(_anchor, fallback_from_raw)` shape;
that shape is the bug. The rule must derive every value from the raw
dataset columns (or `_raw_log`) on its own. The linter enforces this as
ERR-027. ExtraHop's `_detection_category` is the model to follow: the
parser stamps it, but the MODEL deliberately does not read it.
