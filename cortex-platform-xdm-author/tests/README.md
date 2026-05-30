<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# tests/

Python stdlib integrity tests for the `cortex-platform-xdm-author` bundle.

These tests guard the bundle's own shape: JSON validity, SPDX headers, frontmatter ordering, doc-to-schema consistency, ASCII-only and no-emphasis text hygiene, MAPPED-header template completeness, and the bundled linter's behaviour on a small set of fixtures. They also exercise the user-facing path for linting an XQL rule via `../scripts/lint_rule.py`. The manual grep recipe in `../SKILL.md` is the documented fallback for hosts without Python.

## Run

From the bundle root:

```sh
python3 -m unittest discover -v -s tests
```

From anywhere:

```sh
python3 -m unittest discover -v -s /path/to/cortex-platform-xdm-author/tests
```

Python 3.9+ stdlib only. No `pip install`. No Node. No other dependencies.

## What each test guards

| File | Guards | Symptom of a regression |
| --- | --- | --- |
| `test_field_anchors.py` | Field-anchor JSON shape; top-1 candidate for about 13 well-known synonyms (`src`, `dst`, `user_agent`, `hostname`, etc.); the synonym normaliser matches the `lookup_anchor.py` rules; a gibberish input returns zero matches. | Anchor index regenerated and a known mapping drifted, or the JSON file corrupted. |
| `test_asset_integrity.py` | Required top-level files present; every source file UTF-8 decodes; every source file carries the AGPL-3.0-or-later SPDX header in its first 10 lines; SKILL.md line 1 is `---` with `name` plus `description` in the frontmatter; LICENSE first line names AGPL; every markdown file is ASCII-only outside fenced code blocks; markdown outside fenced code carries no bold or italic emphasis; no file contains the legacy "Built with the GoCortex XQL IDE" tagline. | A required file was renamed or removed, SPDX header lost, frontmatter regressed, LICENSE replaced, or a publish-blocker (em-dash, arrow glyph, bold prose, tagline) leaked back into the bundle. |
| `test_doc_consistency.py` | Every `xdm.` path cited in any reference file or the template appears in the authoritative `references/xdm-schema.md` list (or is on a documented allow-known-bad list of counter-examples); every `XDM_CONST.` cited likewise appears in `references/xdm-const.md`; every relative markdown link resolves to an existing file. | A reference invented a path or constant that does not exist, or a markdown link broke after a rename. |
| `test_header_template.py` | `assets/modeling_header_template.xql` contains every required MAPPED-header row (vendor / product / dataset, description, mapping section, NOT MAPPED block, SPDX); starts with a `//` comment; ends with `;`; no leading pipe on the first stage after the MODEL header. | Template rewrite dropped a required section, or introduced a structural defect every emitted rule would inherit. |
| `test_lint_rule.py` | The bundled `scripts/lint_rule.py` fires on fixtures that violate ERR-012, ERR-013, ERR-014, ERR-015, ERR-016, ERR-017, ERR-018, ERR-024, ERR-027 (and INFO-012 when two of those land adjacent), and stays silent on the well-formed counter-example and on a self-sufficient derivation that no longer reads the anchor. Also smoke-tests the CLI (exit codes, JSON output shape). ERR-019, ERR-025, INFO-006, and WARN-020 / WARN-030 / WARN-035 are out of scope for the syntactic linter (dataflow- or XDM-schema-dependent); not exercised here. | The linter regressed on a known parser-conformance trap, or its CLI contract drifted. |
| `test_profile_log.py` | The bundled `scripts/profile_log.py` detects JSON, CEF, and key=value format fixtures; recovers nested array paths (`transactions[].http.method` on the AcmeShield WAF fixture); flags object-array discriminators (`phase` on the WAF transactions); surfaces named header-pair entries (`headers[name=User-Agent]`); computes null rates accurately (`session.user_id` null in event 1, present in event 2, null_rate 0.5); attaches plausible XDM candidate suggestions per field. Also smoke-tests the CLI (exit codes, text format, JSON shape). | Format detection, flattening, type inference, discriminator detection, or anchor lookup regressed. |
| `_helpers.py` | (Not a test file.) Shared bundle-root walker and file iterators used by the test files above. | -- |

## Adding a new integrity check

1. Decide which existing file it belongs in (or create a new `test_<topic>.py` if it is a new topic).
2. Import from `_helpers` (`bundle_root`, `read_text`, `read_json`, `iter_source_files`, `iter_reference_md_files`) rather than walking paths inline. That keeps location-of-bundle logic in one place.
3. If the check is a "deliberate counter-example is allowed" pattern (the ERR-016 examples in `pitfall-traps.md` reference non-existent paths on purpose), add the exception to the relevant `ALLOW_KNOWN_BAD_*` constant in `test_doc_consistency.py` with a one-line written reason.

## What these tests DON'T cover

- Behavioural assertion of the upstream IDE rules engine. The standalone linter shipped with this bundle covers a syntactic subset only (no XDM schema, no dataflow inference); the in-repo engine has the full coverage and is tested separately.
- Host integration. Whether a particular host actually picks up the bundle correctly is not something Python can determine.
