<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Authentication-event mandatory mapping

Authentication events feed the XDM authentication story and identity
analytics. The story is only created automatically when a fixed set of
XDM fields is mapped. A mandatory field left unmapped drops the event
from the story and from identity analytics, so this reference is the
authoritative checklist for any rule that models a login, logon, MFA,
SSO, or other credential-validation event.

Classification is PER RECORD. A feed rarely holds only logins, so decide
the authentication tag and the mandatory set on each record from its own
discriminators, not as one constant across the feed. Records in the same
dataset that are not authentication (a command execution, a bare flow, a
line the rule does not recognise) take their own treatment and, if
unrecognised, the catch-all -- never a forced authentication tag. See
[record-classification.md](record-classification.md).

This guidance is host-agnostic and format-agnostic. Extraction differs
per source format (syslog RFC 3164 / RFC 5424, JSON, JSONL, CEF, LEEF,
key=value), but the XDM target fields and their requirement level are
identical in every case. Map them in the MODEL rule after extraction.

## When this applies (auto-detection)

Treat a sample as an authentication event whenever its field names or
values carry a login / logon / sign-in / MFA / SSO / credential signal,
regardless of vendor. Common signals:

- Field names containing `login`, `logon`, `signin`, `auth`, `authn`,
  `mfa`, `2fa`, `otp`, `sso`, `saml`, `oauth`, `kerberos`, `ntlm`,
  `credential`, `password`, `upn`, `idp`.
- Event-type or action values such as `user.authentication.sso`,
  `microsoft.login.success`, `LOGIN_FAILED`, `logged in`, `mfa challenge`.

`scripts/profile_log.py` reports this signal in an `authentication`
block of the worksheet so the detection is deterministic rather than a
judgement call. When detected, apply the mandatory set below.

Network is the foundational layer beneath this one: when the
authentication log also carries the full transport flow (both endpoint
addresses, a port, and a protocol -- a VPN login, an SSH session, a
gateway sign-in), the event is ALSO a network connection. Apply the
mandatory set in [network-mapping.md](network-mapping.md) on top of
this one, with the union of the story tags in ONE
`xdm.event.tags = arraycreate(...)`. Add the deployment / transport
markers the record earns: `XDM_CONST.EVENT_TAG_VPN` for a VPN login,
`XDM_CONST.EVENT_TAG_SAAS` for a SaaS IdP (Okta, Entra ID, Ping),
`XDM_CONST.EVENT_TAG_CLOUD` for a cloud-provider console, or
`XDM_CONST.EVENT_TAG_ONPREM` for on-premises directory auth. The tag set
is closed to six members ([xdm-const.md](xdm-const.md)).

When detected, `scripts/scaffold_rule.py` pre-populates the mandatory
set: it pads the fields that have an official placeholder (tags,
operation, service, ip_protocol, the transport ports, target.ipv4),
sets `xdm.event.type` to `authentication`, and lists the fields that
must come from the raw log (`xdm.source.user.upn`, `xdm.source.ipv4`,
`xdm.event.original_event_type`, `xdm.event.outcome`) as TODOs rather
than padding them with a static value the platform would reject.

Enforcement is advisory. `scripts/lint_rule.py` classifies a MODEL rule
as authentication either from an explicit XDM marker (the
`EVENT_TAG_AUTHENTICATION` tag, an `OPERATION_TYPE_AUTH_*` operation, or
`authentication` in `xdm.event.type`) or from a broader auth literal
(`login`, `logon`, `signin`, `mfa`, `sso`, ...) in an event-classification
field such as `xdm.event.original_event_type = "user.login"`, so a rule
that models authentication without ever using an explicit marker is still
caught. It raises WARN-042 (warning
severity, never an error) for each mandatory field that an auto-detected
authentication rule leaves unmapped, and also for each mapped mandatory
field whose value violates the closed vocabulary the story demands (the
wrong const, a static source address, or a list where a string is
required). Value conformance is conservative: only a definitively wrong,
self-contained literal is flagged, so a value resolved from a temp, an
xdm read, or a const expression is never second-guessed. The linter never
blocks on this and the exit code stays 0. The author decides; the warning
is a reminder.

## Mandatory fields (all 14 must be mapped)

| XDM target | Type | Notes |
| --- | --- | --- |
| `xdm.source.ipv4` | string | External source IP the IdP / SaaS observed. Map from the raw field that best represents the real client (prefer pre-proxy `client_ip` / `source_ip` / `original_client_ip`). Never static, empty, or a list. |
| `xdm.source.port` | integer | Map the real value; otherwise `to_integer(0)`. |
| `xdm.target.ipv4` | string | Map a real value if present; otherwise the empty string `""`. Do not map a list. |
| `xdm.target.port` | integer | Map the real value; otherwise `to_integer(0)`. |
| `xdm.network.ip_protocol` | integer (enum) | Assign the appropriate `XDM_CONST.IP_PROTOCOL_*` (interactive auth over TCP -> `IP_PROTOCOL_TCP`; pad `IP_PROTOCOL_IP` when absent). |
| `xdm.event.type` | string | Resolve to a value that contains `authentication`. |
| `xdm.event.tags` | array | Must include `XDM_CONST.EVENT_TAG_AUTHENTICATION` on the authentication records. Assign per record via one `if()` so non-auth records in the same feed get their own tags (or blank); add `EVENT_TAG_VPN` / `EVENT_TAG_SAAS` / `EVENT_TAG_CLOUD` / `EVENT_TAG_ONPREM` when earned. See [record-classification.md](record-classification.md). |
| `xdm.event.operation` | enum | Derive the specific `XDM_CONST.OPERATION_TYPE_*` from the event: `OPERATION_TYPE_AUTH_LOGIN` (password login), `OPERATION_TYPE_AUTH_MFA` (involves MFA), `OPERATION_TYPE_AUDIT` (authorization / accounting). There is NO neutral member, so NEVER blind-default to `AUTH_LOGIN` -- when the event kind is genuinely unclear, leave the field unmapped (or `""`) rather than asserting an operation the log does not describe. |
| `xdm.event.original_event_type` | string | The raw vendor event name exactly as logged (e.g. `user.authentication.sso`, `microsoft.login.success`). |
| `xdm.event.outcome` | string (enum) | Only `XDM_CONST.OUTCOME_SUCCESS` or `XDM_CONST.OUTCOME_FAILED`, and only on conclusive events. Do not set on intermediate steps. |
| `xdm.auth.service` | string | The authentication service NAME, derived from the vendor auth protocol / type / mechanism field (`Kerberos`, `NTLM`, `OAuth2`, `SAML`, `SSO`, `RADIUS`, `TACACS+`, `LDAP`, ...). A free string, NOT a role: never `"SP"` / `"IDP"` (a retired misconception -- no such XDM values exist). Normalise via an if()-chain ending in a raw passthrough; pad `"Login"` when the log carries no service field. See "Deriving xdm.auth.service" below. |
| `xdm.source.user.upn` | string | The authenticated identity, ALWAYS UPN-shaped (`jane.doe@company.com`). Cannot be empty. This is the central correlation key across IdPs -- it is `upn`, not `username`. When the raw identity may be bare, synthesise the shape: `if(tmp_username contains "@", tmp_username, tmp_username != null, concat(tmp_username, "@localhost"))`. |
| `xdm.source.user.identity_type` | string (enum) | The nature of the authenticated principal. Derive the `XDM_CONST.IDENTITY_TYPE_*` member: `IDENTITY_TYPE_USER` for a human principal (the common case -- anytime a real UPN is present), `IDENTITY_TYPE_MACHINE` for a computer account (name ends `$`), `IDENTITY_TYPE_BUILTIN` for a well-known OS account, `IDENTITY_TYPE_VIRTUAL` for a managed / virtual account. Fall back to `IDENTITY_TYPE_UNKNOWN` only when no principal resolves. See "Deriving xdm.source.user.identity_type" below. |
| `xdm.source.user.user_type` | string (enum) | The account class. Derive the `XDM_CONST.USER_TYPE_*` member: `USER_TYPE_REGULAR` is the default (~90% of principals), `USER_TYPE_MACHINE_ACCOUNT` when the account name ends `$`, `USER_TYPE_SERVICE_ACCOUNT` for a service-account naming convention (`svc_` / `svc-` prefix, `service` in the name, a GCP `*.iam.gserviceaccount.com` identity). ALWAYS emit the derivation (defaulting to `USER_TYPE_REGULAR`), keyed on an explicit account-type field when the log carries one, otherwise on the principal name. See "Deriving xdm.source.user.user_type" below. Distinct from `xdm.source.user.identity_type`. |

Placeholder policy for the mandatory set:

- Integer fields with no source value -> `to_integer(0)` (`xdm.source.port`,
  `xdm.target.port`).
- `xdm.target.ipv4` is a string here -> a real value, or the empty
  string `""`. Never a list.
- `xdm.source.ipv4` must always come from the raw log -- never a static
  string, list, or empty string.
- `xdm.event.outcome` resolves to `XDM_CONST.OUTCOME_SUCCESS` or
  `XDM_CONST.OUTCOME_FAILED` only.
- The event time (generated time) is mapped automatically; do not set it
  manually.

Note on identity: `xdm.source.user.upn` is the mandatory key. The
human-readable display name is the optional `xdm.source.user.username`
below -- do not substitute one for the other.

The upn value must ALWAYS be UPN-shaped (`user@domain`). A direct
mapping (`xdm.source.user.upn = tmp_upn`) is allowed ONLY when the source
field is a UPN by definition -- `userPrincipalName`, an email address,
an IdP login id. For every other identity source, or whenever there is
any doubt, use the shape-guard idiom: pass a value that already carries
`@` through unchanged, and synthesise a domain for a bare principal.

```
    xdm.source.user.upn = if(
        tmp_username contains "@", tmp_username,
        tmp_username != null, concat(tmp_username, "@localhost"))
```

When the source is known to be bare (a TACACS principal, a Windows
`TargetUserName`, an sshd user), the short form
`if(tmp_username != null, concat(tmp_username, "@localhost"))` is equivalent.
Never emit `xdm.source.user.upn = tmp_username` for a possibly-bare
identity -- the linter raises an advisory WARN-042 for a bare
identifier whose name does not itself indicate a UPN source. The same
shape rule applies to `xdm.target.user.upn` when a rule maps it.

## Deriving xdm.event.operation

`xdm.event.operation` is an `XDM_CONST.OPERATION_TYPE_*` enum with no
neutral member, so always DERIVE the right member from the event before
considering a fall-back. Match the event signal (in the vendor event
name / action / sub-type) to the operation:

| Event signal (name / action / value) | Operation |
| --- | --- |
| login, logon, log-on, sign-in, sign-on, sso, interactive logon, password login | `XDM_CONST.OPERATION_TYPE_AUTH_LOGIN` |
| mfa, 2fa, otp, push, verify, second factor, step-up | `XDM_CONST.OPERATION_TYPE_AUTH_MFA` |
| authorization, authorisation, accounting, command accounting, audit, policy evaluation | `XDM_CONST.OPERATION_TYPE_AUDIT` |
| none of the above can be determined | leave unmapped (or `""`) -- never guess |

The match is on the event's classification field, not on a field name
alone. Prefer an `if()` chain keyed on the vendor event value, for
example `if(tmp_factor != null, XDM_CONST.OPERATION_TYPE_AUTH_MFA, tmp_event
contains "login", XDM_CONST.OPERATION_TYPE_AUTH_LOGIN)`. Only when the
event kind is genuinely ambiguous does the field stay unmapped -- the
advisory WARN-042 then reminds, which is correct.

## Deriving xdm.source.user.identity_type

`xdm.source.user.identity_type` classifies the nature of the
authenticated principal. It is a scalar `XDM_CONST.IDENTITY_TYPE_*`
enum, and unlike `xdm.event.operation` it HAS a neutral member
(`IDENTITY_TYPE_UNKNOWN`), so a safe fall-back always exists. Even so,
derive the specific member: an authentication event carries a mandatory
UPN, so the principal is almost always a human user.

The derivation is on the principal value (and any explicit account-type
field), not on the log format -- the same logic applies to JSON and to
a syslog payload once the account has been extracted into a temp. Check
the signals in order:

| Principal / account signal | identity_type |
| --- | --- |
| An explicit vendor account-type field says machine / computer / device | `XDM_CONST.IDENTITY_TYPE_MACHINE` |
| Account name ends with `$` (AD computer account, e.g. `WIN-DC01$`) | `XDM_CONST.IDENTITY_TYPE_MACHINE` |
| Managed / virtual identity: `NT SERVICE\...`, gMSA, IIS app-pool | `XDM_CONST.IDENTITY_TYPE_VIRTUAL` |
| Well-known OS account: `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, `ANONYMOUS LOGON`, `root` | `XDM_CONST.IDENTITY_TYPE_BUILTIN` |
| A human principal -- a UPN, email, or ordinary username (the common case) | `XDM_CONST.IDENTITY_TYPE_USER` |
| No principal resolves / genuinely indeterminate | `XDM_CONST.IDENTITY_TYPE_UNKNOWN` |

When the log carries an explicit account-type field, key on it first --
it is more reliable than name-shape heuristics. Otherwise derive from
the principal name. A representative if() chain over an extracted
`tmp_principal` temp:

```
    xdm.source.user.identity_type = if(
        tmp_principal = null, XDM_CONST.IDENTITY_TYPE_UNKNOWN,
        tmp_principal contains "$", XDM_CONST.IDENTITY_TYPE_MACHINE,
        tmp_principal contains "NT SERVICE", XDM_CONST.IDENTITY_TYPE_VIRTUAL,
        lowercase(tmp_principal) ~= "^(system|local service|network service|anonymous logon|root)$",
            XDM_CONST.IDENTITY_TYPE_BUILTIN,
        XDM_CONST.IDENTITY_TYPE_USER)
```

When every principal in the source is a human login (a typical IdP or
SaaS feed), the short form is enough: `if(tmp_principal != null,
XDM_CONST.IDENTITY_TYPE_USER, XDM_CONST.IDENTITY_TYPE_UNKNOWN)`.

Note: `xdm.source.user.identity_type` (the nature of the account --
USER / MACHINE / BUILTIN / VIRTUAL) is distinct from
`xdm.source.user.user_type` (the account class -- REGULAR / SERVICE /
MACHINE), the next mandatory field. Map both.

## Deriving xdm.source.user.user_type

`xdm.source.user.user_type` is a scalar `XDM_CONST.USER_TYPE_*` enum
with three members: `USER_TYPE_REGULAR` (a normal interactive account),
`USER_TYPE_SERVICE_ACCOUNT` (an account a program runs as), and
`USER_TYPE_MACHINE_ACCOUNT` (a computer / host account). There is no
UNKNOWN member, so `USER_TYPE_REGULAR` is the default -- it is correct
for the ~90% of authentication events that are human logins.

A log rarely states the account class outright, so ALWAYS emit the
derivation rather than a bare default: key on an explicit account-type
field when the vendor provides one, otherwise match the principal name
against the well-known service- and machine-account conventions, and
fall through to `USER_TYPE_REGULAR`.

Explicit account-type field first. Our anchor dictionary records these
vendor field names for the account class: `user_type`, `usertype`,
`type`, `cloud_account_type`, and `event_useridentity_type` (AWS
CloudTrail `userIdentity.type`). When one is present, map its value:
`AWSService` / a value containing `service` -> `USER_TYPE_SERVICE_ACCOUNT`;
a value containing `machine` / `computer` -> `USER_TYPE_MACHINE_ACCOUNT`;
otherwise `USER_TYPE_REGULAR`.

Name-convention fallback (real-world patterns, not invented):

| Principal / account-name signal | user_type |
| --- | --- |
| Name ends with `$` (AD computer account; a gMSA is treated as a computer account and also ends `$`) | `XDM_CONST.USER_TYPE_MACHINE_ACCOUNT` |
| `svc_` / `svc-` prefix (Microsoft-recommended service-account convention, e.g. `svc_backup`, `svc-HRDataConnector`) | `XDM_CONST.USER_TYPE_SERVICE_ACCOUNT` |
| `service` anywhere in the name (`service_`, `tmp_service`, `*service*`) | `XDM_CONST.USER_TYPE_SERVICE_ACCOUNT` |
| GCP service account (`*.iam.gserviceaccount.com`; service agents are prefixed `service-`) | `XDM_CONST.USER_TYPE_SERVICE_ACCOUNT` |
| Unix daemon accounts (`www-data`, `nobody`, `daemon`, and similar) | `XDM_CONST.USER_TYPE_SERVICE_ACCOUNT` |
| Anything else (a human principal -- the default) | `XDM_CONST.USER_TYPE_REGULAR` |

A representative if() chain over an extracted `tmp_principal` temp
(machine before service, so a gMSA `$` account is classed as a machine
account; `~=` is a regex match, so one alternation covers the service
conventions):

```
    xdm.source.user.user_type = if(
        tmp_principal = null, XDM_CONST.USER_TYPE_REGULAR,
        tmp_principal contains "$", XDM_CONST.USER_TYPE_MACHINE_ACCOUNT,
        lowercase(tmp_principal) ~= "^svc[-_.]|service|gserviceaccount|^www-data$|^nobody$|^daemon$",
            XDM_CONST.USER_TYPE_SERVICE_ACCOUNT,
        XDM_CONST.USER_TYPE_REGULAR)
```

These are heuristics: a real user whose name happens to contain
"service" is misclassified, but the cost is low and `USER_TYPE_REGULAR`
catches everything the patterns miss. Only extend the service-account
pattern list from real vendor conventions -- never invent a prefix.

## Deriving xdm.auth.service

`xdm.auth.service` is the authentication service NAME -- the protocol,
mechanism or service that performed the authentication (`Kerberos`,
`NTLM`, `OAuth2`, `SAML`, `SSO`, `RADIUS`, `TACACS+`, `LDAP`, `Login`,
`MFA`, ...). It is a free String, NOT a role: there is no `"SP"` /
`"IDP"` in XDM. Derive it from the vendor's auth-protocol field --
common source names in the anchor dictionary are `authenticationprotocol`,
`authentication_type`, `authenticationsource`, `protocol`,
`logonprocessname`, `tokenissuertype`.

Normalise the raw value to a canonical service name with an if()-chain,
and end the chain with a raw passthrough so an unrecognised service is
preserved rather than dropped (the standard categorical-field rule).
When the log carries no service field at all, pad `"Login"`.

| Vendor value contains | xdm.auth.service |
| --- | --- |
| `kerberos` / `krb` | `"Kerberos"` |
| `ntlm` | `"NTLM"` |
| `oauth` | `"OAuth2"` |
| `saml` | `"SAML"` |
| `radius` | `"RADIUS"` |
| `tacacs` | `"TACACS+"` |
| `ldap` | `"LDAP"` |
| `sso` | `"SSO"` |
| anything else | the raw value, unchanged (passthrough) |
| no service field in the log | `"Login"` (generic default) |

Representative idiom over an extracted `tmp_svc` temp:

```
    xdm.auth.service = if(
        tmp_svc = null, "Login",
        lowercase(tmp_svc) contains "kerberos", "Kerberos",
        lowercase(tmp_svc) contains "ntlm", "NTLM",
        lowercase(tmp_svc) contains "oauth", "OAuth2",
        lowercase(tmp_svc) contains "saml", "SAML",
        lowercase(tmp_svc) contains "radius", "RADIUS",
        lowercase(tmp_svc) contains "tacacs", "TACACS+",
        lowercase(tmp_svc) contains "ldap", "LDAP",
        lowercase(tmp_svc) contains "sso", "SSO",
        tmp_svc)
```

## Worked shape (JSON source)

A complete MODEL rule that maps all 14 mandatory fields. The extraction
stage changes per format; the assignment stage does not.

```
[MODEL: dataset=vendor_idp_raw]
filter
    _raw_log != null
| alter
    tmp_event = json_extract_scalar(_raw_log, "$.eventType"),
    tmp_upn = json_extract_scalar(_raw_log, "$.actor.alternateId"),
    tmp_src_ip = json_extract_scalar(_raw_log, "$.client.ipAddress"),
    tmp_src_port = json_extract_scalar(_raw_log, "$.client.port"),
    tmp_result = json_extract_scalar(_raw_log, "$.outcome.result"),
    tmp_factor = json_extract_scalar(_raw_log, "$.authenticationContext.method"),
    tmp_svc = json_extract_scalar(_raw_log, "$.authenticationContext.authenticationProvider")
| alter
    xdm.event.type = if(tmp_event != null, "authentication", ""),
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),
    xdm.event.original_event_type = tmp_event,
    xdm.event.operation = if(
        tmp_factor != null, XDM_CONST.OPERATION_TYPE_AUTH_MFA,
        tmp_event != null, XDM_CONST.OPERATION_TYPE_AUTH_LOGIN),
    xdm.event.outcome = if(
        tmp_result ~= "[Ss]uccess", XDM_CONST.OUTCOME_SUCCESS,
        tmp_result != null, XDM_CONST.OUTCOME_FAILED),
    xdm.auth.service = if(
        tmp_svc = null, "Login",
        lowercase(tmp_svc) contains "kerberos", "Kerberos",
        lowercase(tmp_svc) contains "ntlm", "NTLM",
        lowercase(tmp_svc) contains "oauth", "OAuth2",
        lowercase(tmp_svc) contains "saml", "SAML",
        lowercase(tmp_svc) contains "ldap", "LDAP",
        lowercase(tmp_svc) contains "sso", "SSO",
        tmp_svc),
    xdm.source.user.upn = tmp_upn,
    xdm.source.user.identity_type = if(
        tmp_upn != null, XDM_CONST.IDENTITY_TYPE_USER,
        XDM_CONST.IDENTITY_TYPE_UNKNOWN),
    xdm.source.user.user_type = if(
        tmp_upn = null, XDM_CONST.USER_TYPE_REGULAR,
        tmp_upn contains "$", XDM_CONST.USER_TYPE_MACHINE_ACCOUNT,
        lowercase(tmp_upn) ~= "^svc[-_.]|service|gserviceaccount",
            XDM_CONST.USER_TYPE_SERVICE_ACCOUNT,
        XDM_CONST.USER_TYPE_REGULAR),
    xdm.source.ipv4 = tmp_src_ip,
    xdm.source.port = to_integer(to_number(tmp_src_port)),
    xdm.target.ipv4 = "",
    xdm.target.port = to_integer(0),
    xdm.network.ip_protocol = XDM_CONST.IP_PROTOCOL_TCP
;
```

## Optional fields (map when the source provides them)

These enrich the story but are not required for it to be created. Map
them when present; omit them otherwise.

| XDM target | Notes |
| --- | --- |
| `xdm.event.outcome_reason` | Normalise provider error strings into one supported reason value (`user_does_not_exist`, `bad_credentials`, `account_locked`, `mfa_failure`, and similar). |
| `xdm.event.description` | Deterministic `concat()` summary; see [transformation-patterns.md](transformation-patterns.md). |
| `xdm.event.operation_sub_type` | The auth method (`password`, `sms`, `voice`, `application`, and similar). Distinct from the mandatory `xdm.event.operation`. |
| `xdm.source.user.identifier` | Persistent canonical id (GUID / SID). |
| `xdm.source.user.username` | Human-readable display name. NOT the identity key. |
| `xdm.source.user_agent` | Full user-agent string of the client. |
| `xdm.auth.privilege_level` | `XDM_CONST.PRIVILEGE_LEVEL_GUEST` / `PRIVILEGE_LEVEL_USER` / `PRIVILEGE_LEVEL_ADMIN` / `PRIVILEGE_LEVEL_SYSTEM`. |
| `xdm.logon.type` | `XDM_CONST.LOGON_TYPE_INTERACTIVE` / `LOGON_TYPE_SERVICE`. |
| `xdm.source.host.device_id` | Stable per-device id; fall back to source IP when absent. |
| `xdm.source.host.hostname` | Device name. |
| `xdm.source.host.device_category` | Client class (`Computer`, `Mobile`, `Tablet`, `IOT`). |
| `xdm.source.host.os_family` | `XDM_CONST.OS_FAMILY_WINDOWS` / `OS_FAMILY_MACOS` / `OS_FAMILY_LINUX`. For a mobile OS with no listed constant, omit the constant and keep the raw string in `xdm.source.host.os`. |
| `xdm.source.host.os` | Raw OS string. |
| `xdm.source.application.name` | Browser vendor. |
| `xdm.source.application.version` | Browser version. |
| `xdm.target.resource.id` | Accessed resource / app id. |
| `xdm.target.resource.name` | Readable accessed resource / app name. |
| `xdm.source.location.city` | Geo of the source. The companion geo leaves are `xdm.source.location.country`, `xdm.source.location.region`, `xdm.source.location.continent`, `xdm.source.location.timezone`, `xdm.source.location.latitude`, `xdm.source.location.longitude`. |
| `xdm.network.session_id` | Aggregates multiple actions across a session window. |
| `xdm.session_context_id` | Correlates the events of a single auth request / transaction (narrower than `xdm.network.session_id`). |

## AAA gateways (TACACS+, RADIUS, Cisco ISE)

Network-device AAA logs are authentication events with their own
topology and vocabulary. The full worked treatment (nine event shapes
from one daemon family, including legacy freeform lines) is
[worked-examples/08-cisco-tacacs-aaa-multi-shape.md](worked-examples/08-cisco-tacacs-aaa-multi-shape.md).

Topology -- three parties, not two:

| Party | Raw evidence | XDM home |
| --- | --- | --- |
| Principal (the human or service account) | `user=` | `xdm.source.user.upn` (and `.username`) |
| Principal's workstation | `src_ip=` | `xdm.source.ipv4` |
| Network device being accessed | `dvc_ip=` / `at <ip>` | `xdm.target.ipv4` |
| AAA server (validates) | syslog envelope host | `xdm.observer.name` (Stage 0); `xdm.auth.service` = the AAA protocol (`"TACACS+"` / `"RADIUS"`) |

Rules specific to this family:

- Non-UPN identities: AAA principals (`svc_nms1`, `alice.admin`) are
  rarely `user@domain`, but `xdm.source.user.upn` is the mandatory
  correlation key, cannot be empty, and must ALWAYS be UPN-shaped --
  synthesise the shape with
  `if(tmp_user contains "@", tmp_user, tmp_user != null, concat(tmp_user, "@localhost"))`
  and carry the raw principal in `xdm.source.user.username`.
- PERMIT / DENY is the AUTHENTICATION outcome, not a network action.
  Do not tag `XDM_CONST.EVENT_TAG_NETWORK` unless the record carries a
  real transport flow (protocol, ports, byte counts); the profiler
  applies the same rule automatically.
- Accounting Start / Stop is session lifecycle, not success or failure:
  leave `xdm.event.outcome` unset there (the outcome if-chain
  deliberately has no default, so it stays null on lifecycle rows), use
  `XDM_CONST.OPERATION_TYPE_AUDIT` for the operation, and map
  `task_id` -> `xdm.network.session_id` and `elapsed_time` ->
  `xdm.event.duration`. `elapsed_time` is SECONDS and
  `xdm.event.duration` is MILLISECONDS, so multiply by 1000 in function
  form: `to_integer(multiply(to_number(tmp_elapsed), 1000))` (never infix
  `* 1000`). On the authentication shapes, the operation is
  `OPERATION_TYPE_AUTH_LOGIN` and the auth method is `"password"`.
- Command accounting is a COMMAND EXECUTION, not an authentication
  event. An accounting record carrying a command (`cmd=`, `CmdSet`) is
  its own event: set `xdm.event.type` to a process value (for example
  `"process"` -- it must NOT contain "authentication"), map the executed
  command to `xdm.target.process.command_line`, keep operation
  `XDM_CONST.OPERATION_TYPE_AUDIT` with no outcome, put the operator on
  `xdm.source.user.*` and the administered device on `xdm.target.*`, and
  do NOT tag it `EVENT_TAG_AUTHENTICATION`. Only the AUTHEN (login) and
  AUTHOR (authorization) shapes are authentication; see
  [process-mapping.md](process-mapping.md). This is the one AAA record
  kind that leaves the authentication story.
- `xdm.event.outcome_reason`: normalise the known vendor reasons
  (`Bad Password` -> `bad_credentials`, `No such user` ->
  `user_does_not_exist`) and pass unknown reasons through unchanged --
  never force them to a placeholder.
- The vendor `port=` is a TTY / line name (`vty0`, `/dev/pts/7`,
  `rest_http`), never a TCP port: the mandatory integer ports take
  `to_integer(0)` and the line name is documented NOT MAPPED.
- `priv_lvl` -> `xdm.auth.privilege_level` (`15` ->
  `XDM_CONST.PRIVILEGE_LEVEL_ADMIN`, `0` -> `PRIVILEGE_LEVEL_USER`);
  `group` -> `xdm.source.user.groups` via `arraycreate()`.
- Filter diagnostic chatter FIRST (parser hooks, key errors, internal
  bookkeeping lines): keep the event shapes in with an explicit filter
  rather than letting non-events produce near-empty XDM rows.
- Freeform legacy lines: capture addresses with `[\d.]+` only, so a
  placeholder token such as `from async` can never land in an IPv4
  field, and bound the username capture (up to ` from `) so principals
  with embedded spaces survive.

Constants used above live in [xdm-const.md](xdm-const.md); every target
path is defined in [xdm-schema.md](xdm-schema.md).

## Windows logon and Kerberos (4624 / 4625 / 4768 / 4769)

Windows Security logon events are the authentication story: 4624 (success),
4625 (failure), 4634 / 4647 (logoff), and the Kerberos 4768 (TGT request) /
4769 (service ticket) / 4771 (pre-auth failed). Classify per `event_id` within
the `Security` channel, apply the full 14-field mandatory set, and tag
`EVENT_TAG_AUTHENTICATION`. The account that logged on (`TargetUserName` /
`TargetDomainName`) is the source user; `IpAddress` / `IpPort` is the source
endpoint; the DC / target host has no transport endpoint in the record, so the
target tuple takes the auth-story pads. See
[worked-examples/12-windows-logon-kerberos.md](worked-examples/12-windows-logon-kerberos.md).

Logon type. Map the Windows `LogonType` integer to `xdm.logon.type` over the
COMPLETE `LOGON_TYPE` closed list (see [xdm-const.md](xdm-const.md)):

| LogonType | `xdm.logon.type` |
| --- | --- |
| 2 | `LOGON_TYPE_INTERACTIVE` |
| 3 | `LOGON_TYPE_NETWORK` |
| 4 | `LOGON_TYPE_BATCH` |
| 5 | `LOGON_TYPE_SERVICE` |
| 6 | `LOGON_TYPE_PROXY` |
| 7 | `LOGON_TYPE_UNLOCK` |
| 8 | `LOGON_TYPE_NETWORK_CLEARTEXT` |
| 9 | `LOGON_TYPE_NEW_CREDENTIALS` |
| 10 | `LOGON_TYPE_REMOTE_INTERACTIVE` |
| 11 | `LOGON_TYPE_CACHED_INTERACTIVE` |
| 12 | `LOGON_TYPE_CACHED_REMOTE_INTERACTIVE` |
| 13 | `LOGON_TYPE_CACHED_UNLOCK` |

Companion logon fields (map when present): `xdm.auth.service` =
`LogonProcessName` (or `"Kerberos"` on 4768 / 4769); `xdm.logon.package_name` =
`AuthenticationPackageName`; `xdm.logon.is_elevated` from `ElevatedToken`
(`%%1842` -> true, `%%1843` -> false).

Kerberos tickets (4768 / 4769). The ticket encryption type and the failure /
error code map to `xdm.auth.kerberos_tgt.*` (4768) or
`xdm.auth.kerberos_tgs.*` (4769). Both are const-typed over large enums whose
COMPLETE code -> constant crosswalk ships as
[../assets/kerberos_crosswalk.json](../assets/kerberos_crosswalk.json); render
the full if-chain with `python3 scripts/kerberos_map.py --render --group
encryption_type` (and `--group error_code`). Windows logs `TicketEncryptionType`
and `Status` as HEX (`0x12`, `0x18`) and `to_number` does not parse hex, so
either match the hex string directly (for the common values) or strip `0x` and
convert before mapping the decimal chain. Derive `xdm.event.outcome` from the
Kerberos `Status` (`0x0` -> SUCCESS, else FAILED) -- a 4771 or a non-zero 4768
Status is a failed pre-authentication.
