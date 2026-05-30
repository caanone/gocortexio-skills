<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# cortex-platform-xdm-author

A GoCortexIO skill bundle. Authors Palo Alto Networks Cortex XSIAM Data Model Rules in Cortex Query Language (XQL) from raw vendor log samples.

## What is in this bundle

- `SKILL.md` -- entry point for a host that supports the on-disk skill convention. Describes scope, inputs, outputs, the authoring workflow, and the hard rules.
- `references/` -- on-demand reference markdown covering XQL language surface, modelling rule structure, parser idioms, the XDM field list, the XDM_CONST closed-list constants, extraction and transformation patterns, pitfall traps, and known compatibility issues.
- `scripts/` -- three stdlib-only Python helpers: `profile_log.py` (turns a raw log sample into a JSON worksheet of fields, types, null rates, object-array discriminators, and ranked XDM candidates), `lookup_anchor.py` (queries the shipped field-anchor synonym index), and `lint_rule.py` (standalone syntactic linter for a single rule file).
- `assets/` -- the field-anchor synonym index used by `lookup_anchor.py`, plus a MAPPED-header template for new rules.
- `tests/` -- Python stdlib bundle-integrity tests; see `tests/README.md`.
- `LICENSE` -- AGPL-3.0-or-later, shipped with the bundle so the licence travels with the content if the bundle is copied standalone.

## Compatible hosts

The bundle follows the on-disk skill convention: a `SKILL.md` at the bundle root plus optional `references/`, `scripts/`, and `assets/` siblings. Any host that loads skills from this layout can use it. The bundle is host-agnostic; nothing in it depends on a particular runner or model. If the host does not support the convention, the markdown is still usable as plain documentation.

## Standalone use

The only runtime dependency is Python 3.9+ stdlib.

- All `SKILL.md` and `references/` content is self-contained. The workflow, parser idioms, XDM schema, and `XDM_CONST` closed-list constants are documented in full.
- `scripts/profile_log.py` reads a raw log sample and emits a structured field worksheet. Offline; uses only the shipped anchor index.
- `scripts/lookup_anchor.py` queries `assets/field_anchors.json` directly.
- `scripts/lint_rule.py` runs the syntactic linter against a single rule file. It covers ERR-012, ERR-013, ERR-014, ERR-015, ERR-016, ERR-017, ERR-018, ERR-024, and the INFO-012 cascade hint. ERR-019 (every `_temp` reaches an `xdm.*` assignment), ERR-025, INFO-006, and WARN-020 / WARN-030 / WARN-035 need dataflow or XDM-schema analysis and are out of scope -- verify by hand or via the GoCortex XQL IDE in-repo engine, which carries the full rule set.
- The MAPPED-header template in `assets/modeling_header_template.xql` is self-contained.

If no Python interpreter is available, fall back to the references as the authoritative checklist: walk [references/parser-idioms.md](references/parser-idioms.md) (ERR-012 through ERR-019, plus the (xi) / (xii) idioms; ERR-019 is the dataflow check `lint_rule.py` does not perform, so trace every `_temp` to an `xdm.*` consumer by eye), [references/modeling-rules.md](references/modeling-rules.md) (validation checklist), and [references/pitfall-traps.md](references/pitfall-traps.md) before emitting the rule.

## Installing

Copy or symlink the bundle directory into the skills directory the host expects. Consult the host's documentation for that path. Once the bundle is in place, the host loads `SKILL.md` automatically.

If the host does not support the on-disk skill convention, load `SKILL.md` and the references by hand into the session.

## Licence

AGPL-3.0-or-later. See [LICENSE](LICENSE).
