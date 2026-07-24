<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Cloud audit-log mapping (AWS / Azure / GCP)

Cloud management-plane audit logs -- AWS CloudTrail, Azure Activity and Entra ID
(Azure AD) sign-ins, GCP Cloud Audit Logs -- are JSON, deeply nested, and share
one shape: an identity performed a named API action on a resource, with an
outcome. This reference maps that shape to XDM correctly FROM FIRST PRINCIPLES
(the providers' own action-naming conventions plus the authoritative XDM schema)
-- not by copying any pre-existing content pack.

## The cloud classification model

Classify each record on the same three-field model as endpoint telemetry, plus
the cloud entity:

- `xdm.event.type` = the service / source label (AWS `eventSource`, the Azure
  resource provider, the GCP `serviceName`) -- a stable source string, not a
  hand-written semantic label.
- `xdm.event.original_event_type` = the raw action (AWS `eventName`, Azure
  `operationName`, GCP `protoPayload.methodName`).
- `xdm.event.operation` = the derived `XDM_CONST.OPERATION_TYPE_*` verb (see the
  per-provider tables below).
- `xdm.event.tags` = the story: a management API call is CLOUD
  (`arraycreate(XDM_CONST.EVENT_TAG_CLOUD)`); a console login / interactive
  sign-in is the AUTHENTICATION story on a cloud plane
  (`arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION, XDM_CONST.EVENT_TAG_CLOUD)`
  and the full authentication mandatory set from
  [authentication-mapping.md](authentication-mapping.md)); a SaaS admin audit is
  SAAS. Classify per record (see [record-classification.md](record-classification.md)).

## Cloud entity

| XDM target | Source |
| --- | --- |
| `xdm.source.cloud.provider` | the platform: `CLOUD_PROVIDER_AWS` / `_AZURE` / `_GCP` (map from the record's own identity, not a guess) |
| `xdm.source.cloud.region` | AWS `awsRegion`, Azure region, GCP location |
| `xdm.source.cloud.project` / `project_id` | GCP project; AWS `recipientAccountId` / Azure subscription go here or in the account field |
| `xdm.source.cloud.service` | const-typed (`CLOUD_SERVICE_TYPE`) -- set ONLY on a confident known match; otherwise omit (see below) |

Do NOT map the raw service name to `xdm.*.cloud.source_type`. That field is a
banned internal-only XCloud asset attribute (it holds an asset type such as
`t2.micro` / `gp3`), not part of any event data model, and Cortex rejects a
MODEL rule that assigns it -- the linter blocks it with ERR-029. See
[banned-fields.md](banned-fields.md).

CLOUD_SERVICE_TYPE is a very large, fast-moving per-service enum with no complete
authoritative source, so do NOT try to enumerate or complete it. Set
`xdm.source.cloud.provider` reliably, and leave `xdm.source.cloud.service` unset
unless a value confidently matches a known member (see
[xdm-const.md](xdm-const.md)). When the raw service name matches no constant,
record it in the NOT MAPPED block (or `xdm.event.description` if useful), not in a
String field.

## Deriving xdm.event.operation from the action name

Cloud APIs name actions SYSTEMATICALLY, so the verb is derivable from the action
string by convention -- this covers the long tail correctly without a per-action
lookup table. Map to the closed `OPERATION_TYPE` enum (see
[xdm-const.md](xdm-const.md)); leave the field unset only when nothing fits.

AWS CloudTrail `eventName` (PascalCase verb prefix):

| eventName prefix | `xdm.event.operation` |
| --- | --- |
| `Create*`, `Add*`, `Register*`, `Allocate*`, `Provision*`, `Run*`, `Launch*` | `OPERATION_TYPE_CREATE` |
| `Delete*`, `Remove*`, `Deregister*`, `Release*`, `Terminate*`, `Revoke*` | `OPERATION_TYPE_DELETE` |
| `Get*`, `Describe*`, `List*`, `Lookup*`, `Search*`, `Query*`, `Head*`, `BatchGet*` | `OPERATION_TYPE_READ` |
| `Update*`, `Modify*`, `Set*`, `Put*`, `Attach*`, `Detach*`, `Associate*`, `Enable*`, `Disable*`, `Start*`, `Stop*` | `OPERATION_TYPE_UPDATE` |
| `ConsoleLogin`, `AssumeRole*`, `GetSessionToken`, `GetFederationToken` | `OPERATION_TYPE_AUTH_LOGIN` |

Azure `operationName` = `Provider/resourceType/<verb>` where `<verb>` is the last
segment:

| operationName verb | `xdm.event.operation` |
| --- | --- |
| `/write` | `OPERATION_TYPE_UPDATE` (or CREATE for a first write) |
| `/delete` | `OPERATION_TYPE_DELETE` |
| `/read` | `OPERATION_TYPE_READ` |
| `/action` | `OPERATION_TYPE_EXECUTION` |

GCP `protoPayload.methodName` = `service.resource.<Verb>` (last dotted segment):

| methodName verb | `xdm.event.operation` |
| --- | --- |
| `*.Create*`, `*.Insert*` | `OPERATION_TYPE_CREATE` |
| `*.Delete*` | `OPERATION_TYPE_DELETE` |
| `*.Get*`, `*.List*`, `*.Aggregated*` | `OPERATION_TYPE_READ` |
| `*.Update*`, `*.Patch*`, `*.Set*` (e.g. `SetIamPolicy`) | `OPERATION_TYPE_UPDATE` |

## Deriving xdm.event.outcome

- AWS: an `errorCode` (or `errorMessage`) present -> `OUTCOME_FAILED`, else
  `OUTCOME_SUCCESS`. `ConsoleLogin` also carries
  `responseElements.ConsoleLogin` = `Success` / `Failure`.
- Azure: `resultType` = `Success` -> SUCCESS, `Failure` -> FAILED, `Start` /
  `Accepted` -> no outcome (in-progress). Entra sign-in: `status.errorCode == 0`
  -> SUCCESS, else FAILED (the failure reason is `status.failureReason`).
- GCP: `protoPayload.status.code` absent or `0` -> SUCCESS, non-zero -> FAILED
  (the message is `protoPayload.status.message`).

## Actor and target across nested JSON

The identity is buried at different depths per provider -- extract with a deep
`json_extract_scalar` path:

- AWS: `userIdentity.arn` / `userIdentity.userName` /
  `userIdentity.sessionContext.sessionIssuer.userName` -> `xdm.source.user.*`;
  `sourceIPAddress` -> `xdm.source.ipv4` (guard the AWS-service hostname form,
  e.g. `cloudtrail.amazonaws.com`, which is not an IP); `userAgent`.
- Azure: `identity.claims` / `caller` -> `xdm.source.user.*`; `callerIpAddress`
  -> `xdm.source.ipv4`. Entra sign-in: `userPrincipalName` -> `xdm.source.user.upn`.
- GCP: `protoPayload.authenticationInfo.principalEmail` -> `xdm.source.user.upn`
  / `username`; `protoPayload.requestMetadata.callerIp` -> `xdm.source.ipv4`;
  `protoPayload.requestMetadata.callerSuppliedUserAgent`.

Map `xdm.event.description` from the action plus the acted-on resource
(`resources[].ARN` / `resourceName` / the Azure resource id).

## Nested / array shapes

- CloudTrail is often delivered as an envelope object `{ "Records": [ {event}, ... ] }`.
  When the dataset delivers one event per row, extract directly
  (`$.eventName`); when it delivers the envelope, the platform normally splits
  `Records[]` on ingest -- confirm the per-row shape before writing the paths.
- `resources` is an array -- reach an element with
  `arrayindex(..., 0)` over a `json_extract_array` / `json_extract_scalar` path,
  and remember `to_string()` before any downstream string function.
- Deep paths are ordinary `json_extract_scalar(_raw_log, "$.a.b.c")`; there is no
  special syntax for depth.

## What "correct" means here

The vendor packs for these sources are inconsistent; this skill maps from the
providers' documented action conventions and the authoritative XDM schema, and a
mapping-accuracy corpus (tests) pins the result field-for-field. Prefer the
convention rule over hardcoding a handful of sample actions, keep the raw action
in `xdm.event.original_event_type` so nothing is lost, and never invent a
`CLOUD_SERVICE_TYPE` value the source does not confirm.
