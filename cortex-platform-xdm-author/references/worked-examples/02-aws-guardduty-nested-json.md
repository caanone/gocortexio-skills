<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Walkthrough 2 -- AWS GuardDuty (nested JSON, cloud-native)

Vendor / product / dataset: Amazon / GuardDuty / `aws_guardduty_generic_alert_raw`.

What the rule does: maps AWS GuardDuty findings across all six action types (`AWS_API_CALL`, `NETWORK_CONNECTION`, `DNS_REQUEST`, `KUBERNETES_API_CALL`, `PORT_PROBE`, `RDS_LOGIN_ATTEMPT`) plus actionless findings (`AttackSequence`, `MalwareProtection`).

## Synthesised raw log sample

GuardDuty findings arrive as JSON. The XSIAM parser pre-extracts the top-level fields, so `_raw_log` is null and the columns arrive as typed Objects (PascalCase from the AWS Findings API, sometimes camelCase from older ingestion paths -- the rule reads both).

```json
{
  "AccountId": "123456789012",
  "Arn": "arn:aws:guardduty:us-east-1:123456789012:detector/abc/finding/d4e5f6",
  "Id": "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8",
  "Region": "us-east-1",
  "Severity": 7.5,
  "Title": "Unusual API call from suspicious IP",
  "Type": "Recon:IAMUser/UserPermissions",
  "Description": "An IAM principal listed permissions from a known threat-list IP.",
  "Resource": {
    "ResourceType": "AccessKey",
    "AccessKeyDetails": {
      "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
      "PrincipalId": "AIDACKCEVSQ6C2EXAMPLE",
      "UserName": "alice",
      "UserType": "IAMUser"
    }
  },
  "Service": {
    "DetectorId": "abc123",
    "FeatureName": "Service",
    "ResourceRole": "TARGET",
    "Action": {
      "ActionType": "AWS_API_CALL",
      "AwsApiCallAction": {
        "RemoteIpDetails": {
          "IpAddressV4": "198.51.100.42",
          "Organization": {"Asn": "64500", "AsnOrg": "ACME-AS", "Isp": "ACME ISP"}
        },
        "UserAgent": "aws-cli/2.0",
        "ErrorCode": null
      }
    }
  }
}
```

The same finding can also arrive with all keys lowercased (`accountId`, `resource`, `service`, etc.) from the older event-driven pipeline.

## Field inventory

| JSON path | Type | XDM target candidate |
| --- | --- | --- |
| `AccountId` / `accountId` | string | `xdm.source.cloud.project_id`, `xdm.target.cloud.project_id` |
| `Id` / `id` | string | `xdm.event.id`, `xdm.alert.original_alert_id` |
| `Severity` / `severity` | float (1.0-10.0) | `xdm.alert.severity` (banded) |
| `Title` / `title` | string | `xdm.alert.name` |
| `Type` / `type` | string | `xdm.alert.subcategory` |
| `Resource.ResourceType` | string | `xdm.target.resource.type` |
| `Resource.AccessKeyDetails.UserName` | string | `xdm.source.user.username` |
| `Resource.AccessKeyDetails.UserType` | enum | `xdm.source.user.identity_type` (mapped to `XDM_CONST.IDENTITY_TYPE_*`) |
| `Service.Action.AwsApiCallAction.RemoteIpDetails.IpAddressV4` | IPv4 | `xdm.source.ipv4` |
| `Service.FeatureName` | string | `xdm.event.original_event_type`, `xdm.observer.type` |

## Pattern selection

`_raw_log` is null; the GuardDuty payload has been pre-parsed into top-level columns (`AccountId`, `Resource`, `Service`, etc.). The nested objects are accessed with the arrow operator -- `column -> Path.SubField`. This is Pattern D, with the additional wrinkle that EVERY field name has a PascalCase + camelCase pair to support both the official API shape and the older event-driven path.

Coalescing the case-variants once per stage (`coalesce(Resource, resource)` -> `finding_resource`) and then traversing only the unified alias keeps the rule readable.

## Field-anchor lookups

```sh
$ python3 scripts/lookup_anchor.py accountid
  -> xdm.source.cloud.project_id  (score=84, freq=14)

$ python3 scripts/lookup_anchor.py username
  -> xdm.source.user.username  (score=4860, freq=180)

$ python3 scripts/lookup_anchor.py severity
  -> xdm.alert.severity  (score=2240, freq=70) -- but the value here is
    numeric (1.0-10.0), MUST be banded per the transformation patterns

$ python3 scripts/lookup_anchor.py ipaddressv4
  -> no exact match (vendor-specific path; route by directional logic
    using the `is_connection_inbound` / `is_connection_outbound`
    discriminators)
```

For deeply-nested vendor paths (`Resource.AccessKeyDetails.UserName`), the anchor index doesn't carry the full path -- only the leaf (`username`). The rule's job is to derive the leaf via arrow traversal, then assign to the resolved XDM target.

## The MODEL derives everything from raw -- it never reads a parser anchor

GuardDuty's parser stamps two anchors that a MODEL rule must NOT read (Cortex rejects a parser-only `_` column as an unknown field, ERR-027):

- `_action_type` -- the 8-value vocabulary (`AWS_API_CALL`, `NETWORK_CONNECTION`, `DNS_REQUEST`, `KUBERNETES_API_CALL`, `PORT_PROBE`, `RDS_LOGIN_ATTEMPT`, `AttackSequence`, `MalwareProtection`). The MODEL derives the action type from the raw `Action.ActionType` shape itself.
- `_severity_band` -- 3-value bucket (`LOW` <4.0, `MEDIUM` 4.0-6.9, `HIGH` 7.0-8.9). The MODEL drives `xdm.alert.severity` off the numeric `Severity` float (which has its own 4-band vocabulary including `Critical`) and derives the bucketed string from that float, not from any anchor.

## The full rule

```
// AWS GuardDuty -- XDM Data Model Rule
// Dataset: aws_guardduty_generic_alert_raw
// Vendor: Amazon | Product: GuardDuty
//
// Maps AWS GuardDuty findings to the Cortex XDM schema across all six
// action types (AWS_API_CALL, NETWORK_CONNECTION, DNS_REQUEST,
// KUBERNETES_API_CALL, PORT_PROBE, RDS_LOGIN_ATTEMPT) plus actionless
// findings (AttackSequence, MalwareProtection).
//
// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later

[MODEL: dataset = aws_guardduty_generic_alert_raw ]

// -- Stage 1: Initialise root-level aliases ---------------------------------
alter
    finding_resource = coalesce(Resource, resource),
    finding_service = coalesce(Service, service)

// -- Stage 2: Extract action-specific sub-objects ---------------------------
| alter
    finding_process = coalesce(finding_service -> RuntimeDetails.Process{}, finding_service -> runtimeDetails.process{}),
    finding_runtime_context = coalesce(finding_service -> RuntimeDetails.Context{}, finding_service -> runtimeDetails.context{}),
    finding_network = coalesce(finding_service -> Action.NetworkConnectionAction{}, finding_service -> action.networkConnectionAction{}),
    finding_aws_api = coalesce(finding_service -> Action.AwsApiCallAction{}, finding_service -> action.awsApiCallAction{}),
    finding_k8s_api = coalesce(finding_service -> Action.KubernetesApiCallAction{}, finding_service -> action.kubernetesApiCallAction{}),
    finding_rds_login = coalesce(finding_service -> Action.RdsLoginAttemptAction{}, finding_service -> action.rdsLoginAttemptAction{})

// -- Stage 3: Extract common finding and resource fields --------------------
// (Full rule continues in the source pack. The body is ~350 lines covering
// every action type; only the patterns that recur are summarised here.)

| alter
    // Core finding identifiers
    finding_account_id = coalesce(AccountId, accountId),
    finding_arn = coalesce(Arn, arn),
    finding_description = coalesce(Description, description),
    finding_id = coalesce(Id, id),
    finding_region = coalesce(Region, region),
    finding_severity = to_float(coalesce(Severity, severity)),
    // `finding_severity_band` is derived in full from the numeric
    // severity. It is NOT lifted from a parser-stamped `_severity_band`
    // anchor: Cortex validates MODEL rules statically against the dataset
    // schema, where parser-only `_` columns are absent, so reading one is
    // rejected as an unknown field before any coalesce() fallback runs
    // (ERR-027).
    finding_severity_band =
        if(to_float(coalesce(Severity, severity)) < 4.0, "LOW",
           to_float(coalesce(Severity, severity)) < 7.0, "MEDIUM",
           to_float(coalesce(Severity, severity)) < 9.0, "HIGH"),
    finding_title = coalesce(Title, title),
    finding_type = coalesce(Type, type),

    // Resource metadata
    resource_type = coalesce(finding_resource -> ResourceType, finding_resource -> resourceType),
    resource_username = coalesce(
        finding_resource -> RdsDbUserDetails.User, finding_resource -> rdsDbUserDetails.user,
        finding_resource -> AccessKeyDetails.UserName, finding_resource -> accessKeyDetails.userName,
        finding_resource -> KubernetesDetails.KubernetesUserDetails.Username, finding_resource -> kubernetesDetails.kubernetesUserDetails.username),
    resource_user_type = coalesce(finding_resource -> AccessKeyDetails.UserType, finding_resource -> accessKeyDetails.userType),

    // Service action type -- 8-value closed vocabulary
    service_action_type = coalesce(
        _action_type,
        finding_service -> Action.ActionType, finding_service -> action.actionType,
        if(coalesce(Type, type) ~= "^AttackSequence", "AttackSequence"),
        if(coalesce(finding_service -> FeatureName, finding_service -> featureName) ~= "(?i)Malware", "MalwareProtection")),

    // Network action fields
    service_action_network_connection_direction = coalesce(finding_network -> ConnectionDirection, finding_network -> connectionDirection),
    service_action_network_connection_remote_ipv4 = coalesce(finding_network -> RemoteIpDetails.IpAddressV4, finding_network -> remoteIpDetails.ipAddressV4),
    service_action_network_connection_local_ipv4 = coalesce(finding_network -> LocalIpDetails.IpAddressV4, finding_network -> localIpDetails.ipAddressV4),

    // AWS API call fields
    service_action_api_call_remote_ipv4 = coalesce(finding_aws_api -> RemoteIpDetails.IpAddressV4, finding_aws_api -> remoteIpDetails.ipAddressV4),
    service_action_api_call_user_agent = coalesce(finding_aws_api -> UserAgent, finding_aws_api -> userAgent),
    service_action_api_call_error_code = coalesce(finding_aws_api -> ErrorCode, finding_aws_api -> errorCode)

// -- Stage 4: Post-extraction directional flags + protocol normalisation ----
| alter
    is_connection_inbound = if(service_action_network_connection_direction != null and service_action_network_connection_direction = "INBOUND"),
    is_connection_outbound = if(service_action_network_connection_direction != null and service_action_network_connection_direction = "OUTBOUND")

// -- Stage 5: Directional IP and port resolution ----------------------------
| alter
    source_ipv4 = if(is_connection_inbound, service_action_network_connection_remote_ipv4,
                     is_connection_outbound, service_action_network_connection_local_ipv4,
                     service_action_api_call_remote_ipv4),
    target_ipv4 = if(is_connection_inbound, service_action_network_connection_local_ipv4,
                     is_connection_outbound, service_action_network_connection_remote_ipv4)

// -- Stage 7: XDM field assignments -----------------------------------------
| alter
    xdm.observer.vendor = "Amazon",
    xdm.observer.product = "GuardDuty",

    xdm.alert.description = finding_description,
    xdm.alert.name = finding_title,
    xdm.alert.original_alert_id = finding_id,
    xdm.alert.severity = if(
        finding_severity >= 9, "Critical",
        finding_severity >= 7 and finding_severity <= 8.9, "High",
        finding_severity >= 4 and finding_severity <= 6.9, "Medium",
        finding_severity >= 1 and finding_severity <= 3.9, "Low",
        finding_severity_band = "HIGH", "High",
        finding_severity_band = "MEDIUM", "Medium",
        finding_severity_band = "LOW", "Low",
        to_string(finding_severity)),
    xdm.alert.subcategory = finding_type,

    xdm.event.description = finding_description,
    xdm.event.id = finding_id,
    xdm.event.type = "ALERT",
    xdm.event.operation_sub_type = service_action_type,

    xdm.source.cloud.project_id = coalesce(/* api_call remote account */ finding_account_id),
    xdm.source.cloud.provider = XDM_CONST.CLOUD_PROVIDER_AWS,
    xdm.source.cloud.region = finding_region,
    xdm.source.ipv4 = source_ipv4,
    xdm.source.user.username = resource_username,
    xdm.source.user.identity_type = if(
        resource_user_type = "Root",         XDM_CONST.IDENTITY_TYPE_BUILTIN,
        resource_user_type = "IAMUser",      XDM_CONST.IDENTITY_TYPE_USER,
        resource_user_type = "AssumedRole",  XDM_CONST.IDENTITY_TYPE_MACHINE,
        resource_user_type = "FederatedUser", XDM_CONST.IDENTITY_TYPE_VIRTUAL,
        resource_user_type = "AWSAccount",   XDM_CONST.IDENTITY_TYPE_MACHINE,
        resource_user_type = "AWSService",   XDM_CONST.IDENTITY_TYPE_MACHINE,
        resource_user_type = "Directory",    XDM_CONST.IDENTITY_TYPE_USER,
        resource_user_type != null,          XDM_CONST.IDENTITY_TYPE_UNKNOWN),

    xdm.target.cloud.project_id = finding_account_id,
    xdm.target.cloud.provider = XDM_CONST.CLOUD_PROVIDER_AWS,
    xdm.target.cloud.region = finding_region,
    xdm.target.ipv4 = target_ipv4,
    xdm.target.resource.id = finding_arn,
    xdm.target.resource.type = resource_type;
```

The above shows the structural skeleton. The complete shipped rule adds: K8s-specific fields and source-IP arrays, RDS login-attempt mapping, the full HTTP method / response code `XDM_CONST` if-chain (one branch per code), and runtime-monitoring process / target-process / kernel-module fields. The port-probe handling is shown in full below, because it is the single most common place a GuardDuty rule silently drops data.

## PORT_PROBE -- the array trap

`Service.Action.PortProbeAction.PortProbeDetails` is a JSON ARRAY, not an object. A single finding routinely carries several probe entries, each with its own remote IP (the attacker), local IP (the probed host) and local port (the probed port):

```json
"PortProbeAction": {
  "Blocked": false,
  "PortProbeDetails": [
    { "RemoteIpDetails": {"IpAddressV4": "198.51.100.0"}, "LocalIpDetails": {"IpAddressV4": "10.0.0.23"}, "LocalPortDetails": {"Port": 80,  "PortName": "HTTP"} },
    { "RemoteIpDetails": {"IpAddressV4": "203.0.113.7"},  "LocalIpDetails": {"IpAddressV4": "10.0.0.23"}, "LocalPortDetails": {"Port": 443, "PortName": "HTTPS"} }
  ]
}
```

The trap: a bare arrow that traverses THROUGH the array returns null, because the arrow operator expects an object at `PortProbeDetails`, not a list.

```
// DO NOT -- arrow through an array yields null; ports and all-but-first IP are lost
service_action_port_probe_remote_ipv4 = finding_service -> Action.PortProbeAction.PortProbeDetails.RemoteIpDetails.IpAddressV4
```

The fix follows Pattern D': cast the array INLINE with `-> []` in every projection (never bind an array-of-objects to a temp -- Cortex rejects struct-bound array temps, see [extraction-patterns.md](../extraction-patterns.md) Pattern D'), project ONE scalar per `arraymap`, drop nulls with `arrayfilter`, then take `[0]` for the representative scalar. Project the full attacker-IP list into the array sink so no probe entry is lost. PORT_PROBE has no `ConnectionDirection`, so it needs its own branch: remote IP is the source (attacker), local IP and local port are the target (probed host).

```
// -- Stage 6: port-probe scalar + array resolution --------------------------
// Cast PortProbeDetails inline per projection. Do NOT bind it to a temp.
| alter
    // representative scalars (first surviving element of the probe array)
    port_probe_remote_ipv4 = arrayindex(arrayfilter(arraymap(
        coalesce(finding_service -> Action.PortProbeAction.PortProbeDetails[],
                 finding_service -> action.portProbeAction.portProbeDetails[]),
        "@element" -> RemoteIpDetails.IpAddressV4), "@element" != null), 0),
    port_probe_local_ipv4 = arrayindex(arrayfilter(arraymap(
        coalesce(finding_service -> Action.PortProbeAction.PortProbeDetails[],
                 finding_service -> action.portProbeAction.portProbeDetails[]),
        "@element" -> LocalIpDetails.IpAddressV4), "@element" != null), 0),
    port_probe_local_port = to_integer(arrayindex(arrayfilter(arraymap(
        coalesce(finding_service -> Action.PortProbeAction.PortProbeDetails[],
                 finding_service -> action.portProbeAction.portProbeDetails[]),
        "@element" -> LocalPortDetails.Port), "@element" != null), 0)),
    // every probing remote IP, deduped, so multi-entry probes are not lost
    port_probe_remote_ipv4_all = arraydistinct(arrayfilter(arraymap(
        coalesce(finding_service -> Action.PortProbeAction.PortProbeDetails[],
                 finding_service -> action.portProbeAction.portProbeDetails[]),
        "@element" -> RemoteIpDetails.IpAddressV4), "@element" != null))

// -- Stage 6 (continued): fold port-probe into the directional resolution ----
| alter
    source_ipv4 = coalesce(source_ipv4, port_probe_remote_ipv4),
    target_ipv4 = coalesce(target_ipv4, port_probe_local_ipv4)
```

XDM assignment for the probe (remote = source, local/port = target):

```
    xdm.source.ipv4 = source_ipv4,
    xdm.source.host.ipv4_addresses = if(
        array_length(port_probe_remote_ipv4_all) > 0, port_probe_remote_ipv4_all, null),
    xdm.target.ipv4 = target_ipv4,
    xdm.target.port = port_probe_local_port,
```

`xdm.target.port` here is a representative scalar (the first surviving probe entry). A finding that probes several local ports cannot fit them all in one scalar port field, so the full attacker-IP multiplicity is preserved in `xdm.source.host.ipv4_addresses` while the probed port stays a single representative value. If every probed port matters downstream, carry the joined `LocalPortDetails.Port` list into `xdm.event.description` as an auxiliary sink.

## Array hotspots across finding types

PORT_PROBE is not the only array. Across the full GuardDuty finding set the following paths arrive as arrays; a bare arrow that traverses through any of them returns null. Cast with `[]` and project with `arraymap` + `arrayfilter` + `arrayindex` (scalar) or map into an array XDM sink (list). Ranked by how many finding types carry each:

| JSON array path | Why it matters | XDM handling |
| --- | --- | --- |
| `Resource.InstanceDetails.NetworkInterfaces[]` (nested `PrivateIpAddresses[]`, `Ipv6Addresses[]`, `SecurityGroups[]`) | present on most EC2 findings | nested arraymap into `xdm.source.host.ipv4_addresses` / `ipv6_addresses` |
| `Service.Evidence.ThreatIntelligenceDetails[].ThreatNames[]` | near-universal threat-intel labels | join into `xdm.event.description` or map to `xdm.alert.risks` |
| `Service.Action.KubernetesApiCallAction.SourceIps[]` | actor IPs for every K8s finding | `arrayindex(...,0)` to `xdm.source.ipv4`, full list to `xdm.source.host.ipv4_addresses` |
| `Resource.S3BucketDetails[]` (and `[].Tags[]`) | S3 detail is itself an array, easy to miss | `arrayindex(...,0)` for the representative bucket |
| `Service.Action.PortProbeAction.PortProbeDetails[]` | multi-entry probes | see the PORT_PROBE section above |
| `Service.EbsVolumeScanDetails...ThreatNames[].FilePaths[]`, `Service.MalwareScanDetails.Threats[].ItemPaths[]` | malware scan results, array-in-array | project file paths into a description sink |
| `Service.Detection.Sequence.Signals[].SignalIndicators[].Values[]` (AttackSequence) | arrays-of-arrays-of-arrays; cannot be flattened to scalars | pick a representative element, or model in a dedicated rule |
| `Service.RuntimeDetails.Process.Lineage[]` | process ancestry on runtime findings | project to a parent-process description |

## Key decisions called out

- PascalCase + camelCase dual-keying. Every read coalesces both forms. Failing to do this means rows from the older event pipeline silently fail to extract.
- `finding_severity` as float, then banded. AWS gives a 1.0-10.0 float. `xdm.alert.severity` is a categorical string, so the rule bands to `Critical` / `High` / `Medium` / `Low` per the GuardDuty documented bands. The band is derived from the numeric field; the MODEL does not read any parser-stamped `_severity_band` anchor (ERR-027).
- Directional resolution via `is_connection_inbound / is_connection_outbound` flags. For `NETWORK_CONNECTION` findings, the same `LocalIp` / `RemoteIp` fields are SOURCE or TARGET depending on direction. For API-call findings, the API caller is always SOURCE. The flags are derived once and re-read across stage 5.
- `XDM_CONST.IDENTITY_TYPE_*` mapping. Closed-list mapping for the IAM user types. `FederatedUser` -> `VIRTUAL`, `AWSService` -> `MACHINE`, `Root` -> `BUILTIN`. Anything else -> `UNKNOWN`. Speculative additions (`THREAT_CATEGORY_SECURITY`, `CLOUD_PROVIDER_ORACLE`) cause hard validation errors per the closed-list rule in [xdm-const.md](../xdm-const.md).
- `xdm.source.cloud.provider = XDM_CONST.CLOUD_PROVIDER_AWS` hardcoded -- every GuardDuty finding is AWS by definition.
