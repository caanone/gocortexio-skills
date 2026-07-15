<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# MITRE ATT&CK mapping

Two XDM fields carry ATT&CK, and BOTH are arrays (Datatype String,
Dataclass Array):

- `xdm.alert.mitre_tactics` -- `XDM_CONST.MITRE_TACTIC_*` (14 members).
- `xdm.alert.mitre_techniques` -- `XDM_CONST.MITRE_TECHNIQUE_*` (the full
  ATT&CK enum).

The XDM constants use the ATT&CK NAME, not the `T####` id, so a T-code
must be translated. The full authoritative crosswalk (T-code -> constant,
plus the 14-tactic keyword table) ships as
[../assets/mitre_crosswalk.json](../assets/mitre_crosswalk.json) and is
resolved by `scripts/mitre_map.py`. Every emitted constant is validated
against the documented enum; anything unresolved is OMITTED, never
invented.

The profiler flags a MITRE reference in a `mitre` block of the worksheet
when a field NAME carries `mitre` / `att&ck` / `technique` / `tactic` /
`ttp`, or a value is shaped like an ATT&CK id (`T####` / `TA####`).

## 1. Direct mapping (the log carries explicit ATT&CK ids or names)

When a field holds ATT&CK ids or canonical names, translate them with
`scripts/mitre_map.py` and map into the array field:

```
python3 scripts/mitre_map.py --kind technique --ids T1078,T1059 --temp _tech
python3 scripts/mitre_map.py --kind tactic    --names "Credential Access,Execution"
```

The id form emits an `arraymap` if-chain over the extracted temp (an
array of the log's ids), resolving each to its constant and dropping
unknowns:

```
    xdm.alert.mitre_techniques = arraymap(_tech, if(
        "@element" = "T1078", XDM_CONST.MITRE_TECHNIQUE_VALID_ACCOUNTS,
        "@element" = "T1059", XDM_CONST.MITRE_TECHNIQUE_COMMAND_AND_SCRIPTING_INTERPRETER,
        null))
```

Only the ids present in the log are emitted, so the rule stays small even
though the crosswalk covers the whole enum.

## 2. Fuzzy tactic mapping (a category / name field carries tactic words)

When there is no explicit id but an alert `category` / `name` /
`description` field carries tactic language ("Credential Access",
"Lateral Movement", ...), map the 14 tactics by high-confidence keyword.
Because `xdm.alert.mitre_tactics` is an ARRAY, the match is MULTI-MATCH --
every tactic whose keywords appear is collected, not first-match-wins:

```
python3 scripts/mitre_map.py --fuzzy-tactics --temp _category
```

emits one `if()` per tactic, `arraycreate`-wrapped and `arrayfilter`-pruned:

```
    xdm.alert.mitre_tactics = arrayfilter(arraycreate(
        if(lowercase(_category) contains "credential access" or lowercase(_category) contains "credential dumping", XDM_CONST.MITRE_TACTIC_CREDENTIAL_ACCESS, null),
        if(lowercase(_category) contains "lateral movement", XDM_CONST.MITRE_TACTIC_LATERAL_MOVEMENT, null),
        ...one branch per tactic...
    ), "@element" != null)
```

- A record whose category contains both "credential access" and "lateral
  movement" yields a two-element array.
- A record matching nothing yields an empty array -- never a guessed
  tactic. This mirrors the skill's no-guess rule elsewhere.

Keep it high-confidence. The keyword table
([../assets/mitre_crosswalk.json](../assets/mitre_crosswalk.json),
`tactic_keywords`) holds only the canonical tactic phrase plus a few
strong, security-specific synonyms. Point the chain at the most
tactic-like field (category / name), not a broad free-text blob, to keep
precision high.

## Techniques are not fuzzy-matched

The technique enum is far larger and its names are too ambiguous for
keyword matching, so techniques are mapped ONLY from explicit ids / names
(mechanism 1). Do not keyword-guess a technique.

## Datatype reminder

Both fields are arrays -- always build them with `arraymap` /
`arraycreate` (never a bare scalar). See
[xdm-schema.md](xdm-schema.md) and [record-classification.md](record-classification.md).
