<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Changelog

Per-version change history for the `cortex-platform-xdm-author` bundle. The current version is declared in the `SKILL.md` frontmatter; this file is not loaded at runtime and exists for provenance.

## 1.8.0

First stable release of the 1.8 line, consolidating the 1.8.0-beta series. Hardens three ways a rule could bake in sample-specific data instead of the authoritative domain:

- A const-typed enum must be mapped over its COMPLETE set. `xdm.network.http.response_code` now ships a full 60-code crosswalk (`assets/http_status_crosswalk.json`, rendered by `scripts/http_status_map.py`) and lint WARN-048 flags any partial `if()`-chain.
- An unused `tmp_` scratch field is now a hard block (ERR-019) on EVERY dataset, since Cortex rejects an unused field regardless of the dataset suffix.
- A hardcoded, sample-derived customer literal (a tenant path / host / IP / ID baked into a `contains` / `=` branch) is flagged WARN-049. Extract the value dynamically or keep it in a free-String field, and never invent a classification the source does not define.

Also in 1.8.0:

- Every skill-authored scratch temp moved to the `tmp_` prefix. The `_` prefix is reserved by the platform for internal / system-generated fields, so a rule must never create a `_`-prefixed field; lint ERR-028 blocks it (reading `_raw_log` is fine). No `fields -` cleanup is needed, as a MODEL rule surfaces only `xdm.*`.
- Source-reference intake step: after profiling a sample, the skill asks once for the format-matched reference (OpenAPI / JSON Schema for JSON, a message / mnemonic doc for syslog, a CEF / LEEF or column dictionary otherwise), proceeds sample-only when none is available, and stamps `GOCORTEX_SKILLS_SOURCE_BASIS` in provenance.
- Prepend-robust syslog extraction: every generated syslog rule captures identically whether a record arrives direct off the device or behind an intermediate relay that prepends its own `<PRI>` header. A relay-aware Stage 0 (greedy `^.*` prefix -> origin host + origin PRI) plus token-anchored body extraction, enforced by advisory lint WARN-047.
- Cloud audit-log mapping: AWS CloudTrail, Azure Activity and Entra sign-in, GCP Cloud Audit, each with a convention-derived operation verb and a permanent scored mapping-accuracy harness (`scripts/score_mappings.py`).
- Endpoint telemetry mapping: Linux / Windows / Sysmon process, registry and logon events, with complete OPERATION_TYPE / LOGON_TYPE / Kerberos crosswalks and advisory WARN-050.
- Broader vendor coverage through new verified extraction recipes and field anchors: Celonis audit-log authentication plus Nokia SR OS, Cisco Catalyst, Cisco WLC, HPE ArubaOS-Switch, Huawei VRP and Apache / Tomcat.

## 1.7.2

- Authoritative MITRE ATT&CK mapping: the full T-code -> constant crosswalk plus high-confidence multi-match tactic keywords.
- Fixed the top-of-rule comment order: SPDX licence always first, then the REVIEW UNMODELLED query and a RAISE SKILL ISSUES pointer always last.

## 1.7.0

- Classification became a PER-RECORD decision: every rule decides `xdm.event.type` and `xdm.event.tags` on each record from its own discriminators (not one label stamped across the feed), drawing tags from the full closed six-member `EVENT_TAG` enum (authentication, network, cloud, saas, onprem, vpn).
- Catch-all sentinel: any record a rule cannot classify receives `xdm.event.original_event_type = "GOCORTEX_UNMODELLED"` with blank tags, so a `datamodel` search never returns fewer rows than the raw dataset.

## 1.6.1

- Added a process / command-execution mapping capability and a verified extraction-recipe layer.
- Corrected `xdm.auth.service` to the authentication service name.
- Broadened vendor field-name coverage.
