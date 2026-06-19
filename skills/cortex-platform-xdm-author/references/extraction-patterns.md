<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Extraction patterns -- A, B, C, D

These are the four canonical shapes for getting vendor fields out of `_raw_log` (or out of pre-parsed top-level columns). Pick the pattern that matches the structure of the incoming log; do NOT copy a skeleton verbatim.

For a complete, validated rule that exercises each pattern end to end, see the matching walkthrough in [worked-examples.md](worked-examples.md) rather than reconstructing from the skeleton.

## Decision tree -- which pattern applies?

```
Inspect _raw_log first.

_raw_log contains a JSON string                  -> Pattern A or C
_raw_log contains a syslog / text string         -> Pattern B
_raw_log is null, fields are top-level columns   -> Pattern D
```

Critical: calling `json_extract_scalar` on a null `_raw_log` returns null for EVERY field. If `_raw_log` is null, use Pattern D (arrow operator on top-level columns).

The bundled `scripts/profile_log.py` reports a `detected_format` field on its worksheet that maps onto the decision tree above (`json`, `jsonl` -> Pattern A or C depending on the column shape; `cef`, `leef`, `syslog-3164`, `syslog-5424` -> Pattern B; `kv` -> Pattern A applied to a parsed top-level column). When the worksheet's `object_arrays` section names a discriminator key (`phase`, `role`, `type`, etc.), Pattern D' applies and the projection must filter on that discriminator value before reading the inner scalars.

## Pattern A -- JSON field extraction (`json_extract_scalar`)

When: `_raw_log` is a JSON string, OR the parser delivers a single top-level column whose value is a JSON string.

```
alter
    _<temp_a> = json_extract_scalar(<json_column>, "$.<field_a>"),
    _<temp_b> = json_extract_scalar(<json_column>, "$.<nested>.<field_b>")
| alter
    <XDM_FIELD_1> = _<temp_a>,
    <XDM_FIELD_2> = _<temp_b>;
```

Always cast non-string columns with `to_string()` before passing to `json_extract_scalar`:

```
_field = json_extract_scalar(to_string(<column>), "$.<path>")
```

## Pattern B -- Syslog / positional parsing (`split` + `arrayindex`)

When: `_raw_log` is a single string with positional, delimiter-separated fields (Squid-style, CSV, etc.).

For a syslog source (a `<NNN>` priority token at the start of `_raw_log`), parse the envelope first with the one canonical idiom in [syslog-envelope.md](syslog-envelope.md) -- it captures the host and decodes the priority once, the same way for every vendor -- then apply Pattern B to the payload body. Do not hand-roll a header regex anchored on a vendor literal; the linter flags that as WARN-040.

```
alter
    _<inner> = arrayindex(regextract(_raw_log, "<wrapper_regex>"), 0)
| alter
    _parts = split(_<inner>, " ")
| alter
    _<field_n> = arrayindex(_parts, <N>)
| alter
    <XDM_FIELD> = _<field_n>;
```

Rules:

- Always wrap `arrayindex()` output in `to_string()` before passing to `split()` or `regextract()`. Without the cast, you get a generic parse error.
- Hyphen `"-"` means empty in Squid format. Check `field != "-"` before assigning to XDM.
- The syslog hostname gives the observer / intermediary device identity.

## Pattern C -- Label/value array extraction (`regextract` on key/value)

When: A field contains a JSON-style array of `{label, value}` pairs and the labels you need are not at fixed JSON paths.

```
# string values
_<temp> = arrayindex(regextract(<source>,
    "\"<Label Text>\"\s*,\s*\"value\"\s*:\s*\"([^\"]+)\""), 0)

# numeric values
_<temp> = arrayindex(regextract(<source>,
    "\"<Label Text>\"\s*,\s*\"value\"\s*:\s*(\d+)"), 0)
```

## Pattern D -- Arrow operator on parsed JSON objects

When: `_raw_log` is null and the XSIAM ingestion parser has already broken the event into top-level columns whose values are JSON objects (not strings). Traverse with the arrow operator; append `{}` for sub-objects, `[]` for arrays.

```
alter
    _<sub_obj> = <column> -> <Key>.<SubKey>{},
    _<scalar>  = <column> -> <Key>.<Field>
| alter
    <XDM_FIELD> = _<scalar>;
```

Note: chained arrows (`a -> b -> c`) are invalid. Use dot notation (`a -> b.c`) or `json_extract_scalar` for deep paths.

Note: for arrays of objects (e.g. `participants[]`), do NOT bind the filtered struct to an underscore temp and dereference it later. Cortex rejects struct-bound temps. Use the per-scalar projection (Pattern D' below).

## Pattern D' -- Role-filtered array of objects (per-scalar projection)

When: A column is an array of objects where each element has a discriminator field (`role`, `type`, `party`) and you need one or more scalar fields from the matching element.

Canonical pattern (verified against the live ExtraHop XDM model rule): project ONE scalar at a time inside `arraymap`, drop nulls with `arrayfilter`, then take `[0]`. Never bind the whole struct.

```
# DO NOT (parser rejects -- ERR-017)
alter
    _chosen = arrayindex(arrayfilter(<array_column> -> [],
        "@element" -> <role_field> = "<role_value>"), 0)
| alter
    _field_a = _chosen -> <field_a>;     // struct passthrough -- BLOCKED

# DO (one alter line per scalar; repeat per field)
alter
    _<chosen_field_a> = arrayindex(arrayfilter(arraymap(
        <array_column> -> [],
        if("@element" -> <role_field> = "<role_value>",
           "@element" -> <field_a>, null)),
        "@element" != null), 0),
    _<chosen_field_b> = arrayindex(arrayfilter(arraymap(
        <array_column> -> [],
        if("@element" -> <role_field> = "<role_value>",
           "@element" -> <field_b>, null)),
        "@element" != null), 0)
| alter
    <XDM_FIELD_A> = _<chosen_field_a>,
    <XDM_FIELD_B> = _<chosen_field_b>;
```

Rules:

- Cast the JSON-string column ONCE per projection with `<col> -> []` (see [parser-idioms.md](parser-idioms.md) ERR-018). Without the cast, array functions reject the column.
- `arraymap` with an inner `if()` that returns the inner scalar when the role matches and null otherwise. Then `arrayfilter("@element" != null)` to drop non-matching positions, then `arrayindex(..., 0)` to take the first surviving scalar.
- One projection per inner field. Do NOT bind the filtered struct array to a temp variable.
- Inner field access uses `"@element" -> field_name` (lowercase as it appears in the source JSON).
- Mirror the projection set for victim/target with `role = "victim"`; do not reuse the offender variables.

## Pattern -- MITRE arraymap with no double-wrap

When: The log already provides an array of MITRE IDs and you need an array of XDM_CONST values. The arraymap result IS already an array -- do NOT wrap in `arraycreate()`.

```
alter
    _<ids> = arraymap(<array_column> -> [], "@element" -> <id_field>)
| alter
    <XDM_FIELD> = arraymap(_<ids>, if(
        "@element" = "<ID_1>", XDM_CONST.<NAME_1>,
        "@element" = "<ID_2>", XDM_CONST.<NAME_2>));
```

Contrast: when the log gives a SINGLE id (not an array), wrap with `arraycreate(if(...))` instead. The choice depends on the SHAPE of the source field, not on the destination. See [transformation-patterns.md](transformation-patterns.md) section "Array MITRE mapping" for the full ID->constant rule.

## Pattern -- Banded numeric scoring

When: A vendor numeric score (0-100, 1-10, etc.) needs to be mapped to a banded XDM severity string or `XDM_CONST.LOG_LEVEL_*`. Highest threshold first; final branch fires only when the score is non-null.

```
<XDM_FIELD> = if(
    <score> >= 80, "Critical",
    <score> >= 50, "High",
    <score> >= 30, "Medium",
    <score> != null, "Low");
```

For an XDM_CONST destination, every branch returns an `XDM_CONST.*` value, never a raw string. See [transformation-patterns.md](transformation-patterns.md) section "XDM_CONST-required fields".

## Pattern -- Object-type-gated IP mapping

When: A column may hold an IP, a hostname, a username, or a tenant identifier depending on a sibling discriminator (`object_type`, `entity_kind`). Assign `xdm.source.ipv4` only when the discriminator says the value is an IP.

```
alter
    _<ip> = if(_<object_type> = "ipaddr", _<object_value>, null)
| alter
    xdm.source.ipv4 = _<ip>,
    xdm.source.host.ipv4_addresses = if(_<ip> != null, arraycreate(_<ip>), null);
```

## Pattern -- Scalar-from-array via arrayindex + arrayfilter

When: A vendor array (e.g. `categories[]`) needs to populate a scalar XDM_CONST destination (e.g. `xdm.alert.category`). Map every array element to the closest XDM_CONST with `arraymap`+`if`, drop nulls with `arrayfilter`, then take the first match with `arrayindex`. First match wins. Preserve the full joined text in `xdm.event.description` for human context.

```
alter
    _<joined> = arraystring(<array_column>, ", ")
| alter
    <XDM_SCALAR_FIELD> = arrayindex(arrayfilter(arraymap(<array_column>, if(
        "@element" ~= "(?i)<token_a>", XDM_CONST.<NAME_A>,
        "@element" ~= "(?i)<token_b>", XDM_CONST.<NAME_B>)),
        "@element" != null), 0),
    xdm.event.description = concat("Categories: ", _<joined>);
```

## Anchor pattern -- risk-detection block (banded score + THREAT_CATEGORY scalar + offender/properties.* coalesce)

When: Pattern D detection logs that deliver a numeric `risk_score`, a vendor `categories[]` array, AND a `participants[]` role-tagged actor array with an offender entity (and possibly secondary identity hints under `properties.*`). This is the canonical ExtraHop-RevealX shape but the same anchor applies to any vendor that mixes these three signals (NDR / CDR / SIEM detections, CrowdStrike fac alerts, etc).

The three sub-patterns below MUST appear together; any one missing is a regression.

```
alter
    _risk_score = to_number(risk_score),
    _categories_arr = categories -> [],
    _props_username = properties -> username,
    _offender_username = arrayindex(arrayfilter(arraymap(participants -> [],
        if("@element" -> role = "offender", "@element" -> username, null)),
        "@element" != null), 0)
| alter
    // (1) banded severity -- NEVER raw to_string() on the score
    _severity = if(
        _risk_score >= 80, "Critical",
        _risk_score >= 50, "High",
        _risk_score >= 30, "Medium",
        _risk_score != null, "Low"),
    _log_level = if(
        _risk_score >= 80, XDM_CONST.LOG_LEVEL_CRITICAL,
        _risk_score >= 50, XDM_CONST.LOG_LEVEL_ERROR,
        _risk_score >= 30, XDM_CONST.LOG_LEVEL_WARNING,
        _risk_score != null, XDM_CONST.LOG_LEVEL_INFORMATIONAL),
    // (2) categorical enum array -> THREAT_CATEGORY scalar (first match)
    _category_const = arrayindex(arrayfilter(arraymap(_categories_arr, if(
        "@element" ~= "(?i)brute",        XDM_CONST.THREAT_CATEGORY_BRUTE_FORCE,
        "@element" ~= "(?i)phish",        XDM_CONST.THREAT_CATEGORY_PHISHING,
        "@element" ~= "(?i)dos|ddos",     XDM_CONST.THREAT_CATEGORY_DOS,
        "@element" ~= "(?i)botnet",       XDM_CONST.THREAT_CATEGORY_BOTNET,
        "@element" ~= "(?i)backdoor",     XDM_CONST.THREAT_CATEGORY_BACKDOOR,
        "@element" ~= "(?i)cryptominer",  XDM_CONST.THREAT_CATEGORY_CRYPTOMINER,
        "@element" ~= "(?i)exfil|data",   XDM_CONST.THREAT_CATEGORY_DATA_THEFT,
        "@element" ~= "(?i)code",         XDM_CONST.THREAT_CATEGORY_CODE_EXECUTION,
        "@element" ~= "(?i)hacktool",     XDM_CONST.THREAT_CATEGORY_HACKTOOL,
        "@element" ~= "(?i)post.?expl",   XDM_CONST.THREAT_CATEGORY_POST_EXPLOITATION,
        "@element" ~= "(?i)protocol",     XDM_CONST.THREAT_CATEGORY_PROTOCOL_ANOMALY)),
        "@element" != null), 0),
    // (3) properties.* identity fallback -- coalesce offender then properties
    _user_username = coalesce(_offender_username, _props_username)
| alter
    xdm.alert.severity = _severity,
    xdm.event.log_level = _log_level,
    xdm.alert.category = _category_const,
    xdm.source.user.username = _user_username,
    xdm.target.user.username = _user_username;
```

Explicitly rejected anti-patterns:

- `xdm.alert.severity = to_string(risk_score)` -- unbanded raw score.
- `xdm.alert.subcategory = arraystring(categories -> [], ", ")` as the sole outlet for `categories[]` -- bypasses THREAT_CATEGORY.
- Dropping `properties.*` with "no XDM sink available" when a `properties.username` (or any `*_username`) is present and the offender username might be null.

## A note on intermediate variables

Underscore-prefixed temporaries (`_<name>`) are conventional in XDM data model rules. The dataset model layer drops these intermediates naturally at query time -- a `| fields -<temp1>, -<temp2>, ...` cleanup stage is NOT idiomatic in an XDM model rule. That cleanup syntax belongs to parsing rules, where intermediates use the `tmp_*` prefix and must be dropped explicitly. The bundled `lint_rule.py` deliberately omits INFO-006 (missing cleanup stage) for MODEL rules on this basis; ignore that finding if a downstream linter reports it.

## Category versus subcategory routing

Both `xdm.alert.category` and `xdm.alert.subcategory` are valid sinks for vendor classification text, but they sit at different levels of the XDM hierarchy and the choice between them is not interchangeable:

- `xdm.alert.category` is an enum-typed field. It MUST be assigned a value from the `XDM_CONST.THREAT_CATEGORY_*` closed list (see [xdm-const.md](xdm-const.md)). Use it when the vendor's classification text maps deterministically to one of the listed constants -- "Phishing", "Brute Force", "DoS", "Botnet", "Backdoor", "Cryptominer", "Data Theft", "Code Execution", "Hacktool", "Post-Exploitation", "Protocol Anomaly".
- `xdm.alert.subcategory` is a free-text String. It accepts the vendor's raw classification verbatim. Use it as the fallback when the vendor text does not match any THREAT_CATEGORY constant, and ALSO use it alongside `xdm.alert.category` to preserve the precise vendor wording when the category is a rough match.

The mandatory ordering when a vendor ships a `categories[]` array or a single classification string:

1. Try `xdm.alert.category` first via an `arrayindex(arrayfilter(arraymap(... XDM_CONST.THREAT_CATEGORY_*)))` chain (see the "Anchor pattern -- risk-detection block" below for the canonical shape).
2. ALSO populate `xdm.alert.subcategory` with the raw joined text (`arraystring(categories, ", ")` for arrays, or the bare string for scalars). This preserves the vendor wording even when the category match succeeded.
3. If step 1 produces no match for ANY array element, leave `xdm.alert.category` unassigned. Do NOT invent a constant; do NOT force the closest-looking match. The subcategory field carries the information.

Anti-pattern: `xdm.alert.subcategory = arraystring(categories, ", ")` as the sole outlet for the vendor categories. This bypasses the enum-typed `xdm.alert.category` entirely and downstream queries that filter on category will miss the rule. Always attempt the category mapping first.
