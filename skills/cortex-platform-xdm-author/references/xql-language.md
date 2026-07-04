<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# XQL language reference

Covers the XQL language as used in data model rules (`[MODEL: dataset=..._raw]`). Data-model-specific structure lives in [modeling-rules.md](modeling-rules.md). Parsing rules (`[INGEST: ...]`) are out of scope for this skill -- see [../SKILL.md](../SKILL.md).

## Rule structure (shared rules)

- First stage after the header has NO leading pipe. Write `filter` or `alter`, not `| filter` or `| alter`. All subsequent stages DO use a leading pipe.
- The entire rule MUST end with a semicolon (`;`). The last field assignment before the semicolon must NOT have a trailing comma.
- Dataset names in the header are NOT quoted. Write `dataset=name_raw` not `dataset="name_raw"`.
- Intermediary (temporary) variables are prefixed with underscore, e.g. `_client_ip`, `_sender_addr`. Every intermediary variable MUST be consumed in a subsequent assignment or passed to another intermediary that is itself consumed. Unused intermediaries cause a BLOCKING validation error: "Data Model Rules contains unused fields".

See [parser-idioms.md](parser-idioms.md) for the twelve non-negotiable parser idioms.

## Extraction functions (used in alter stages)

### `json_extract_scalar(json_string, "$.path.to.field")`

Extracts a scalar value from a JSON string by JSON path. The first argument must be a string. If the column might not be a string, wrap with `to_string()`.

```
json_extract_scalar(to_string(imperva), "$.risk_reason")
```

### `regextract(string, "regex_with_capture_group")`

Returns an ARRAY of capture group matches. Always wrap with `arrayindex(..., 0)` to get the first match.

```
_host = arrayindex(regextract(_raw_log, ">\w+\s+\d+\s+[\d:]+\s+(\S+)\s+accesslogs"), 0)
```

### `split(string, "delimiter")`

Splits a string into an array by delimiter.

```
_parts = split(_stripped_log, " ")
```

### `arrayindex(array, index)`

Returns the element at the given 0-based index from an array.

```
_client_ip = arrayindex(_parts, 2)
```

### `arraycreate(value1, value2, ...)`

Creates an array from scalar values. REQUIRED for Array-type XDM fields.

```
xdm.email.recipients = arraycreate(_recipient)
```

### `arraymap(array, expression)`

Applies an expression to each array element. Use `"@element"` to reference the current item.

```
arraymap(detection_filters, json_extract_scalar("@element", "$.name"))
```

### `arrayfilter(array, condition)`

Filters array elements by condition. Use `"@element"` in the condition.

```
arrayfilter(ip_array, "@element" ~= "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
```

### `arraystring(array, delimiter)`

Joins array elements into a single string with delimiter.

```
arraystring(arraycreate("a", "b"), ", ")
```

### `arraydistinct(array)`

Removes duplicate values from an array.

### `arrayconcat(array1, array2)`

Merges two arrays into one.

### `array_length(array)`

Returns the number of elements in the array.

### `json_extract_array(json_string, "$.path.to.array")`

Extracts an array from a JSON string. Use instead of `json_extract_scalar` when the target value is a JSON array and the XDM field type is Array.

```
_ip_list = json_extract_array(_raw_log, "$.network.ip_addresses")
```

## Transformation functions

### `coalesce(val1, val2, ...)`

Returns the first non-null value.

```
_sender_ip = coalesce(senderIp, SourceIP)
```

### `concat(str1, str2, ...)`

Concatenates strings.

```
xdm.event.description = concat("Event: ", _type, " from ", _sender)
```

### `to_string(value)`

Converts to string. REQUIRED before passing `arrayindex()` output to `split()` or `regextract()`.

```
_sub_a = arrayindex(split(to_string(_result_status), "/"), 0)
```

### `to_number(string)` / `to_integer(string)` / `to_float(value)` / `to_boolean(value)`

Type conversions. `to_number()` returns a float -- integer XDM fields (duration, port, bytes, packets, pid) MUST be wrapped in `to_integer()`. See [parser-idioms.md](parser-idioms.md) idiom (iv) / ERR-015.

```
xdm.event.duration = to_integer(to_number(_ms))
```

### `to_json_string(value)`

Converts a value to a JSON string representation.

### `uppercase(string)` / `lowercase(string)`

Case conversion.

```
_normalised_action = lowercase(_action_type)
```

### `incidr(ip_string, "cidr_range")`

Returns true if the IP address falls within the specified CIDR range. Use for filtering private/public IPs or matching known subnets. `incidr6()` is the IPv6 equivalent.

```
xdm.source.is_internal_ip = if(
    incidr(_src_ip, "10.0.0.0/8") or
    incidr(_src_ip, "172.16.0.0/12") or
    incidr(_src_ip, "192.168.0.0/16"),
    true, false)
```

### `trim(string)` / `replace(string, "old", "new")`

Whitespace trim and string replacement.

### `if(condition1, value1, condition2, value2, ..., default_value)`

Multi-branch conditional. All conditions and values are positional arguments in a flat list. This is NOT if/else syntax -- it is a flat function call.

```
xdm.event.outcome = if(
    Action = "Acc",   XDM_CONST.OUTCOME_SUCCESS,
    Action = "Block", XDM_CONST.OUTCOME_FAILED,
    Action = "Hld",   XDM_CONST.OUTCOME_PARTIAL,
    XDM_CONST.OUTCOME_UNKNOWN)
```

### `parse_epoch(string_value, "MILLIS" or "SECS")`

Parses epoch timestamp string to Timestamp type. `from_epoch` does NOT exist in XQL -- always use `parse_epoch`.

### Arithmetic: `add(a, b)` / `subtract(a, b)` / `multiply(a, b)` / `divide(a, b)`

Infix arithmetic inside `alter` is BANNED -- Cortex parser rejects it with a cascade of generic "parse error" lines. See [parser-idioms.md](parser-idioms.md) idiom (i) / ERR-012.

```
xdm.event.duration = to_integer(subtract(to_number(_end_ms), to_number(_start_ms)))
```

## Arrow operator (`->`)

Used for accessing fields in parsed JSON objects (not strings).

- One level: `column -> FieldName`
- Nested with dot notation: `column -> Parent.Child.Field`
- Array access: `column -> ArrayField[]`
- Inside `arraymap` / `arrayfilter`: use `"@element"` for per-element access.

Chained arrows (`a -> b -> c`) are INVALID. Use dot notation (`a -> b.c`) or `json_extract_scalar`.

JSON-string columns MUST be cast with `-> []` before any array function (`arraymap`, `arrayfilter`, `arraystring`, `arraydistinct`, `array_length`). See [parser-idioms.md](parser-idioms.md) idiom (vii) / ERR-018.

```
arraymap(participants -> [], ...)     // correct
arraymap(participants, ...)           // BLOCKED -- needs -> []
```

## Comparison operators

| Operator | Meaning |
| --- | --- |
| `=` | Equality (NOT `==`) |
| `!=` | Inequality |
| `~=` | Regex match |
| `contains` | Substring check |
| `in` | Set membership |
| `or` / `and` | Combine conditions inside `if()` branches |

Do NOT combine null-comparisons with `and` / `or` inside `if()` predicates. Drop the guard (Cortex propagates null) or nest `if()` calls. See [parser-idioms.md](parser-idioms.md) idiom (ii) / ERR-013.

```
// BANNED
if(_a != null and _b != null, subtract(_b, _a), null)

// allowed
subtract(_b, _a)

// allowed (nested guards)
if(_a != null, if(_b != null, subtract(_b, _a), null), null)
```
