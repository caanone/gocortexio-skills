<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<div align="center">
  <img src="assets/skills.png" alt="Great Skills" width="600"/>
</div>

# GoCortexIO Skills

Portable skill bundles for doing cool stuff with the Palo Alto Networks Cortex Platform. Each subdirectory is one self-contained bundle: a SKILL.md entry point, on-demand `references/` markdown, optional `scripts/` and `assets/`, and an AGPL-3.0-or-later licence file. Bundles follow the on-disk skill convention: a `SKILL.md` at the bundle root plus optional `references/`, `scripts/`, and `assets/` siblings. Any host that loads skills from this layout can use them. Nothing in a bundle is tied to a particular runner or model.

## Responsible use of AI
This project provides AI Skills to enhance and extend your AI workflows. However, **the availability of these skills is not an encouragement, endorsement, or guarantee of safety for uploading confidential, proprietary, or sensitive data into third-party AI platforms.**

This projects skills merely format or route data; the ultimate data security and compliance depend entirely on the underlying AI model or platform you choose to connect them to. In line with the Australian Signals Directorate (ASD) guidelines on [Data leaks and privacy breaches](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/artificial-intelligence-for-small-business#data-leaks-and-privacy-breaches), uploading un-anonymised corporate or personal data into public generative AI systems risks exposing private information, as external providers may retain and reuse your inputs.

Before deploying or experimenting with these skills in a professional setting, you must:

* Perform Internal Security Checks: Consult your organisation's IT security, InfoSec, or legal compliance teams to ensure the use of these tools aligns with your internal AI acceptable use frameworks.
* Verify Corporate AI Policies: Ensure your choice of third-party AI provider has been officially vetted and approved by your company or organisation for handling organisational data.
* Validate the AI Backend: Confirm that your underlying AI environment contractually guarantees data isolation and access control as outlined in the ASD's [AI Data Security Best Practices](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/ai-data-security#best-practices-to-secure-data-for-ai-based-systems).

**Never feed data into a third-party AI system that has not been internally approved by your organisation or that you would not want publicly disclosed.**

## Available bundles

| Bundle | Purpose |
| --- | --- |
| [cortex-platform-xdm-author](cortex-platform-xdm-author/) | Author Cortex XSIAM Data Model Rules in Cortex Query Language (XQL). Produce a complete `[MODEL: dataset=..._raw]` rule from raw vendor log samples, with a MAPPED-header comment block. MODEL-only. |

## Installing a bundle

A bundle is just a directory. Copy or symlink it into the skills directory the host expects, then start the host. Consult the host's documentation for the exact path. If the host does not support the on-disk skill convention, load `SKILL.md` and the references by hand into the session.

## Updating a bundle

The source-of-truth lives here. Edit files under `skills/<bundle-name>/`, then re-copy to any installed location or rely on a symlink. Commit changes to this folder; installed copies are local artefacts and should not be committed.

The `cortex-platform-xdm-author` bundle's `references/` are derived markdown snapshots of the upstream XDM schema, XQL functions, parser-conformance rules, and field-anchor index. When the corresponding upstream source changes (XDM schema, an `XDM_CONST` enum, a parser conformance rule, or the field-anchor table), re-derive the matching reference file so the bundle stays in sync.

## Scope

Each bundle states its own scope in its `SKILL.md`. The `cortex-platform-xdm-author` bundle covers Data Model Rules only; Parsing Rules (`[INGEST: ...]`) and parser-stamped anchor columns are out of scope.

## Runtime dependencies

The `cortex-platform-xdm-author` bundle ships three Python helpers under `scripts/`:

- `profile_log.py` -- static profiler for raw log samples.
- `lookup_anchor.py` -- query the shipped field-anchor synonym index.
- `lint_rule.py` -- standalone syntactic linter for a single rule file.

All three are Python 3.9+ stdlib only: no `pip install`, no Node, no network. They run anywhere a Python interpreter is available. If no Python is available, the reference markdown remains usable as a manual checklist; see the bundle's own `SKILL.md` for the fallback workflow.

## Licence

All bundles are released under the GNU Affero General Public Licence v3.0 or later (AGPL-3.0-or-later). Each bundle ships its own `LICENSE` copy so it remains licensed when installed standalone.
