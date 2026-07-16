<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Record-level classification and the catch-all

Two rules govern how a MODEL rule labels events. Both are about the
INDIVIDUAL record, not the feed as a whole.

1. Classify per record. One dataset almost always carries several
   record kinds -- a firewall feed mixes traffic, VPN logins and admin
   commands; an AAA feed mixes logins, authorizations and command
   accounting. Decide `xdm.event.type` and `xdm.event.tags` from EACH
   record's own discriminators, never as one constant stamped across the
   whole feed.
2. Never drop a record. A `datamodel dataset = X` search must return the
   same row count as the raw `dataset = X`. A MODEL rule that filters
   records out shrinks that count and hides data. The only record a rule
   may drop is a genuinely empty one (`_raw_log = null`); everything
   else must produce a row, and anything the rule cannot classify gets a
   CATCH-ALL row (see below).

## Classify per record with a no-default if()-chain

`xdm.event.tags` is an Array over the closed six-member `EVENT_TAG`
enum (see [xdm-const.md](xdm-const.md)). Assign it ONCE, with an
`if()` whose branches test each record's discriminators and which ENDS
WITH NO DEFAULT -- so a record matching no known kind falls through to
blank tags rather than a guessed marker:

```
    xdm.event.tags = if(
        tmp_is_login != null,   arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),
        tmp_is_vpn != null,     arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION, XDM_CONST.EVENT_TAG_VPN, XDM_CONST.EVENT_TAG_NETWORK),
        tmp_is_flow != null,    arraycreate(XDM_CONST.EVENT_TAG_NETWORK),
        tmp_is_saas != null,    arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION, XDM_CONST.EVENT_TAG_SAAS),
        null)
```

The final bare `null` is deliberate: an unrecognised record carries no
tag. This mirrors the skill's existing idiom of ending a categorical
if-chain without a default when null is the correct value (as with
`xdm.event.outcome` on session-lifecycle rows).

`xdm.event.type` follows the same per-record shape -- it is a free
String, so branch it to the kind each record actually is:

```
    xdm.event.type = if(
        tmp_is_flow != null,  "network",
        tmp_is_cmd != null,   "process",
        tmp_is_login != null, "authentication",
        "GOCORTEX_UNMODELLED")
```

The discriminator temps (`tmp_is_login`, `tmp_is_flow`, ...) are extracted in
an earlier `alter` stage from the record's own markers (a `type=` field,
a `cmd=` token, an action verb, a transport tuple), exactly as the
worked examples do.

## The catch-all: keep the datamodel row count honest

Give every record a home. Filter only the empty ones, then let the
if()-chains label what they recognise and sentinel the rest:

```
[MODEL: dataset = vendor_x_raw]
filter
    _raw_log != null                       // the ONLY record we drop
| alter
    tmp_is_login = ... , tmp_is_flow = ... , tmp_is_cmd = ...   // per-record discriminators
| alter
    xdm.event.type = if(
        tmp_is_flow != null,  "network",
        tmp_is_cmd != null,   "process",
        tmp_is_login != null, "authentication",
        "GOCORTEX_UNMODELLED"),            // catch-all type
    xdm.event.tags = if(
        tmp_is_login != null, arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),
        tmp_is_flow != null,  arraycreate(XDM_CONST.EVENT_TAG_NETWORK),
        null),                             // catch-all: blank tags
    xdm.event.original_event_type = coalesce(tmp_vendor_event_type, "GOCORTEX_UNMODELLED")
;
```

The sentinel `"GOCORTEX_UNMODELLED"` lands in `xdm.event.original_event_type`
(a plain String) ONLY when the record carried no vendor event-type of
its own. Recognised records keep their real vendor type there, so the
sentinel and the real values coexist in one column -- which is what
makes the review query work.

## Always leave the review query in the rule

Every rule carries a commented query so the author can see what did not
classify and grow the rule to cover it:

```
// REVIEW UNMODELLED: list records this rule could not classify --
//   datamodel dataset = vendor_x_raw
//   | filter xdm.event.original_event_type = "GOCORTEX_UNMODELLED"
//   | fields xdm.event.original_event_type, vendor_x_raw._raw_log
```

Replace `vendor_x_raw` with the real dataset. Run it after deploying the
rule; each distinct raw shape it returns is a record kind to add a
branch for.

## Checklist

```
[ ] only filter is _raw_log != null (no discriminator filter that drops rows)
[ ] xdm.event.type and xdm.event.tags assigned per record via if()
[ ] tag if-chain ends with no default -> blank tags on unrecognised records
[ ] only closed EVENT_TAG members used (AUTHENTICATION/NETWORK/CLOUD/SAAS/ONPREM/VPN)
[ ] one xdm.event.tags assignment (never two -- the second overwrites)
[ ] unclassified records carry xdm.event.original_event_type = "GOCORTEX_UNMODELLED"
[ ] the commented REVIEW UNMODELLED query is present with the real dataset
```
