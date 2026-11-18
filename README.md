# Cloudy With a Chance of Tokens

**Cloud app visibility, OAuth context, and exportable evidence—because “probably fine” isn't a security posture.**

A Defender XDR-first investigation companion for Microsoft Defender for Cloud Apps and app governance. Follow the evidence, not just the alert count.

The Cloud App Visibility PowerShell package provides fourteen configured hunting views (five new views are opt-in), read-only telemetry assessment, portable CSV/JSON/HTML reports, source-backed investigation context, and two **optional, disabled-by-default** custom detections. It complements existing identity visibility and native Microsoft detections; it does not try to out-alert your alert queue.

No Sentinel dependency, agent, background service, credential store, or automatic containment. This is an independent package, not a Microsoft product or an installable Defender dashboard.

> **Pilot-ready source, not production-certified magic.** Offline contracts and syntax checks pass. Mocked PowerShell execution is blocked by local signing policy, and no live tenant or KQL validation has been performed. See [Validation](#validation) before deployment.

## The short version

1. Review the evidence and telemetry prerequisites below.
2. Use your trusted code-signing process where required, configure a local tenant file, and run `Plan`.
3. Run read-only `Assess` to check actual data availability.
4. Use `ExportResults` for a portable dashboard snapshot; keep tenant data out of this repository.
5. Consider the optional detections only after overlap review and authorized tenant testing. They remain disabled until you decide otherwise.

## What is included

| Component | Purpose |
|---|---|
| `Invoke-CloudAppVisibility.ps1` | Entry point; defaults to an offline plan with no network or file writes. |
| `CloudAppVisibility.psm1` | Configuration validation, safe rendering, read-only Graph assessment and results export, disabled rule deployment, recovery receipts and guarded rollback. |
| `config.example.json` | Empty tenant-sensitive lists; context-dependent views need configuration, while discovery views can return data. |
| `catalog.json` | Fourteen hunting views and two unchanged opt-in detection definitions. Includes telemetry boundaries and coverage ownership. |
| `evidence.json` | Seven Microsoft reports, attribution boundaries, observed activity versus lab demonstrations, native overlap, and technical references. Research window: March 5–November 17, 2026. |
| `tests` | Dependency-free static checks and mocked PowerShell behavioral tests. |

### Recent threat activity informing the views

These are primary-source observations, **not proof of a missing Microsoft detection**. Full links and limitations are in `evidence.json`.

| Report | Observed behavior | Package treatment |
|---|---|---|
| September 22: EvilTokens | Device-code phishing, Graph discovery, mailbox collection, inbox-rule persistence; Storm-2992 develops/supports the service, not necessarily every intrusion. | Enrich existing alerts and review watched-app access to business-sensitive resources. Do not recreate native device-code/Graph/inbox-rule sequences. |
| September 2: IT support impersonation | External Teams contact, remote support, MSI/Node.js execution, AD discovery, WinRM toward Tier 0. Actor unnamed. | Correlate reviewed native Teams alerts with later endpoint tool execution by the same Entra user. Later identity pivots remain an investigation step. |
| July 23: Q2 email threats | OAuth redirect abuse delivering malware; generic/SaaS-themed Teams identities. Actors unnamed for these examples. | Teams hunting context. OAuth redirect delivery is not misrepresented as consent phishing or token theft; no detection for that delivery chain is shipped. |
| May 4: code-of-conduct phishing | April 14–16 AiTM token capture campaign. Actor unnamed. | Protected-account alert enrichment and follow-on hunting. No invented downstream mailbox behavior or duplicate impossible-travel rule. |
| November 5: Q3 email threats | August device-code salary lures; Teams callers increasingly used ordinary names. Actors unnamed for these examples. | Avoid helpdesk-name-only detection. Call attempts are not successful contacts; the described token-transfer mechanism is not a verified compromise count. |

### November 17 visibility update: applications have identities, too

Five new **hunting-only, opt-in** views add application-identity and connected GitHub context. The two existing detections and their deployment definitions are unchanged. No connectors are installed, no detections are enabled, and no automated response is introduced.

| Evidence addition | Classification | Why it matters |
|---|---|---|
| [Exposed application secrets and agentic tooling, November 5](https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/) | **Observed activity; missed baseline.** Modified November 10, but the substantive change is unverified. The application-credential chain is not attributed to a named actor here. | Stolen application credentials, service-principal authentication and Graph/resource activity need different evidence from a user-consent chain. A November 10 modification is not a November 10 discovery. |
| [Device-code authentication risks for AI coding agents, November 17](https://www.microsoft.com/en-us/security/blog/2026/11/17/the-risks-of-device-code-authentication-for-ai-coding-agents/) | **Controlled lab demonstration**, not an observed campaign. Microsoft says the demonstrated outcomes were not observed in the wild. | Connected GitHub activity and reviewed native alerts can support investigation. Repository, session, memory and conditional remote-control consequences must not be inferred from a single audit row. |

This project owns application/SaaS investigation context. [MDO-Anomalies](https://github.com/homelabber/MDO-Anomalies) owns email/phishing, user-consent and mailbox sequences; [mdi-freshness](https://github.com/homelabber/mdi-freshness) owns AD/Tier-0 sequences; [sentinelheartsnutanix](https://github.com/homelabber/sentinelheartsnutanix) owns Prism telemetry. Existing Microsoft detections remain the starting signal, not competition for another alert.

## Prerequisites and trust

- Windows PowerShell 5.1 or PowerShell 7 on Windows/NTFS; no third-party module is required by the package.
- Appropriate Defender licensing, roles, enabled Cloud Apps connectors and Microsoft 365 activity collection. App governance must be enabled for `OAuthAppInfo`.
- Use your organization's trusted code-signing process for the `.ps1` and `.psm1` files before running them if device policy requires signatures. Do not bypass device protections. Signatures on the module and launcher are both relevant.
- Online modes accept a short-lived **Microsoft Graph** access token as a `SecureString`, acquired through your approved authentication process. The package neither authenticates interactively nor persists tokens. Local JWT checks only guard tenant/audience routing and expiry; Graph performs actual token authentication. Opaque/non-JWT tokens are intentionally unsupported.
- Only the global Microsoft Graph endpoint is supported. Sovereign clouds are not silently redirected.
- Optional application authentication/Graph views require tenant availability and access to `EntraIdSpnSignInEvents` and `GraphAPIAuditEvents`. Verify licensing, ingestion, retention and current tenant schemas. `CloudAppEvents` is not a replacement for either table. A combined view fails if either required source is unavailable rather than silently returning a partial timeline.
- Optional GitHub operation discovery requires the supported GitHub Enterprise Cloud connector, appropriate licensing/permissions, and exact observed `CloudAppEvents.Application` values. Native-alert context separately requires ingested `AlertInfo`/`AlertEvidence` and reviewed alert titles; it does not prove connector health. GitHub OAuth client IDs are not Entra app IDs and are not assumed to appear in `OAuthAppInfo`.

Permissions (delegated or application, with required admin consent/RBAC):

| Operation | Graph permission |
|---|---|
| `Assess`, `Hunt`, `ExportResults`, deployment query preflight | `ThreatHunting.Read.All` |
| Optional custom-rule inventory | `CustomDetection.Read.All` (or `CustomDetection.ReadWrite.All`) |
| `Deploy`, `Rollback` | `CustomDetection.ReadWrite.All`; deployment also needs hunting permission |

Workload-specific scope and Defender roles still apply. Seeing zero rows does not establish complete visibility. `Assess` makes read-only POST requests to the hunting API; it does not create or change rules.

## Start offline

Copy the example configuration through your normal editor/file workflow to a local tenant configuration. Keep it outside shared source control if it contains sensitive identifiers. Set `TenantId` before any online mode.

```powershell
.\Invoke-CloudAppVisibility.ps1 -Mode Plan | ConvertTo-Json -Depth 40
.\Invoke-CloudAppVisibility.ps1 -Mode Plan -ConfigPath 'C:\Security\tenant.json' |
    ConvertTo-Json -Depth 40
```

`Plan` validates configuration, renders definitions and lists blockers. It does **not** claim live KQL compilation, inspect tenant rules, or deploy anything. Both definitions always use `status: disabled`, hourly scheduling and no automated actions.

### Configuration guide

- **GUID arrays:** `ProtectedAccountObjectIds`, `WatchedAppIds`, `ApprovedAppIds` use canonical Entra GUIDs. An app cannot be both watched and approved. `OAuthAppId` is the application's GUID, **not** the numeric Cloud Apps `ApplicationId`.
- **`ProtectedResourceIds`:** exact, case-sensitive `CloudAppEvents.ObjectId` values observed in your tenant. A mailbox address or SharePoint URL is not guaranteed to be the recorded ObjectId. Do not invent mappings.
- **`MonitoredActionTypes`:** exact, reviewed access operations from your tenant. Do not populate with permission-change events if your policy intends resource access. Source audit outcome must be reviewed separately.
- **`NativeTeamsAlertTitles`:** exact native alert titles observed in your tenant. The shipped list is empty because Microsoft says titles can vary. Confirm that `AlertEvidence` identifies the actual internal impacted user via `AccountObjectId`; related/external identities must not be substituted.
- **`RemoteToolFileNames`:** executable basenames only. Defaults are investigation candidates, **not malicious-file signatures**. `msiexec.exe`, `node.exe` and remote-support tools have legitimate uses. Tune before deployment.
- **`ApprovedSequenceDeviceIds`:** exact MDE device IDs to exclude from Teams correlation. These exclusions can hide activity; keep them narrow and review periodically.
- **`ApprovedAppIds`:** exclusions in the protected-account/resource view and protected-resource rule. App timeline and remediation views deliberately still show watched/remediated activity. Approval is not proof an app cannot be compromised.
- **`RemediationRecords`:** objects such as `{ "OAuthAppId": "<actual GUID>", "RemediatedAt": "2026-11-01T12:00:00Z" }`. Use a real past UTC timestamp. The latest recorded cutoff per app is used; this is manual evidence, not automated proof remediation succeeded.
- `LookbackDays`: 1–14 (default 7); `SequenceWindowMinutes`: 1–240 (default 120); `StaleAfterHours`: 1–720 (default 24). Lists are limited to 500 entries.
- Set the three `Reviews` booleans only after the corresponding human reviews. They are acknowledgements, not automatically generated coverage certificates.

### Enable optional hunting without changing detection policy

Existing schema-version-1 tenant files remain supported: omitted new fields default to `false`/empty lists. New fields are validated as JSON booleans or string arrays; unknown fields are still rejected.

- **`EnableApplicationIdentityHunting`** (default `false`): enables the three new application-identity views and adds separate authentication/Graph table probes to `Assess`. Set `WatchedAppIds`; the protected-resource candidate view also needs `ProtectedResourceIds` and `MonitoredActionTypes`.
- **`EnableGitHubHunting`** (default `false`): enables the two GitHub views. Set `GitHubApplicationNames` to exact observed connector `Application` names for operation discovery and `NativeGitHubAlertTitles` to exact reviewed native titles for alert enrichment. Each view requires its own list; the package does not guess names or action mappings.

Both flags gate `Assess`, `Hunt` and `ExportResults` for the new views. Offline `Export` still renders every query for manual review, including disabled optional views. Legacy views keep their existing behavior. Default `Assess` still probes its original six tables and compiles the original nine views; it reports the five optional views as `NotConfigured`. Enabling application hunting adds two table probes, even when watched-app lists still need configuration.

The new protected-resource view includes **non-user or unresolved audit identities**, not a proven app-only token classification. Service/system/unknown types or missing account IDs need source-level validation. It deliberately retains watched applications also listed as approved, so approval does not hide investigation evidence. The existing user-mapped rule keeps its approved-app exclusion and `Regular`/`Admin` restriction.

```powershell
# After updating the local tenant configuration and using approved authentication:
.\Invoke-CloudAppVisibility.ps1 -Mode Assess -ConfigPath $cfg -AccessToken $token
.\Invoke-CloudAppVisibility.ps1 -Mode Hunt -QueryId service-principal-signins -ConfigPath $cfg -AccessToken $token
.\Invoke-CloudAppVisibility.ps1 -Mode ExportResults -QueryId app-graph-timeline `
    -ConfigPath $cfg -AccessToken $token -OutputDirectory 'C:\Security\exports'
```

## Assess and discover

After signing/trusting the scripts through your approved process:

```powershell
$token = Read-Host 'Short-lived Microsoft Graph access token' -AsSecureString
$cfg = 'C:\Security\tenant.json'

.\Invoke-CloudAppVisibility.ps1 -Mode Assess -ConfigPath $cfg -AccessToken $token |
    ConvertTo-Json -Depth 40

.\Invoke-CloudAppVisibility.ps1 -Mode Hunt -QueryId operations -ConfigPath $cfg -AccessToken $token
.\Invoke-CloudAppVisibility.ps1 -Mode Hunt -QueryId teams-alert-discovery -ConfigPath $cfg -AccessToken $token
```

Assessment probes each table separately, then executes each configured hunting query with `take 1`. One missing table does not hide the others. `IdentityLogonEvents` is an optional AD-visibility prerequisite probe, not a dependency of the two shipped rules. `RecentData`, `StaleOrQuiet`, `NoRecentData`, and `UnavailableOrQueryFailed` are distinct. A quiet feed is not automatically broken. OAuth metadata uses `AvailableSnapshot`, not the same freshness assumption as activity feeds.

Add `-IncludeRuleInventory` to retrieve custom rules and identify exact-ID, exact-query-text and display-name overlaps. It **does not enumerate native Cloud Apps/app governance policies** or establish semantic uniqueness. Review native policies, existing AD rules, and other custom rules manually. Inventory failure is reported as unknown/failure, not no overlap.

Graph errors report HTTP status without dumping bearer headers or response bodies. Check permissions and validate the exported query in Advanced Hunting for detailed schema errors. Requests are bounded by a timeout; writes are not automatically retried after ambiguous failures.

## Dashboard-style hunting views

Export the configured views to an **existing** directory:

```powershell
.\Invoke-CloudAppVisibility.ps1 -Mode Export -ConfigPath $cfg -OutputDirectory 'C:\Security\exports'
```

Files use a unique run prefix and are never overwritten. Save each rendered `.kql` as a shared query in Defender Advanced Hunting. The templates in `queries` contain tokens and must be rendered first. This is a collection of tabular/time-binned investigation views, **not an installable Defender dashboard or Sentinel workbook**.

| Query ID | View |
|---|---|
| `operations` | Cloud operations, recent counts, OAuth/user identifier coverage. |
| `app-posture` | Latest supported OAuth app metadata; uses `arg_max` to avoid repeated snapshots. |
| `protected-access` | Configured protected-user or resource audit activity, excluding approved apps. |
| `app-timeline` | Watched-app workload activity in hourly bins, with approximate resource/account counts. |
| `alert-enrichment` | Existing alerts linked to protected users across products; includes existing AD custom alerts if present. |
| `teams-endpoint` | Impacted-user native Teams alert to subsequent same-user endpoint tool execution. |
| `remediation-review` | Event-time activity later than the latest manually recorded remediation cutoff. |
| `watched-protected-access` | Reviewed app + resource + operation intersection with usable impacted-account IDs. |
| `teams-alert-discovery` | Candidate Teams alert titles and evidence roles for manual review; title keyword matching is discovery only. |
| `app-identity-protected-access` | Opt-in non-user/unresolved audit identity candidates for watched app + reviewed operation + protected resource; not proof of app-only authentication. |
| `service-principal-signins` | Opt-in watched-application authentication successes/failures, resource, service principal and IP context. Authentication is not resource access. |
| `app-graph-timeline` | Opt-in parallel application authentication and Graph request timeline; no causal, token or session join. Graph activity may be delegated. Request URIs, scopes and token IDs are deliberately omitted. |
| `github-operations` | Opt-in operation and identifier-coverage discovery for exact configured GitHub connector application names; no assumed token/repository event names. |
| `github-alert-context` | Opt-in reviewed native alert context and impacted-account evidence; retains alerts with no Entra mapping. Does not reconstruct coding-agent sessions, memory or commands. |

The views avoid message subjects, email bodies, process command lines and full raw audit payloads by default. Identifiers and access metadata are still sensitive. Secure exported files and any PowerShell transcripts under your organization's retention policy. API row/time/resource limits apply; a hunting response is not a completeness guarantee. A zero-row view with empty configuration is expected.

### Export the actual results

`Export` still exports **query definitions and an offline plan**. New `ExportResults` runs the existing hunting queries and exports their **returned data**. Same queries, better handoff. No second detection engine hiding in the spreadsheet.

After trusted signing, tenant configuration and approved token acquisition, choose an **existing local directory** with appropriate access controls:

```powershell
# Preview the action: no token, network requests or file writes required.
.\Invoke-CloudAppVisibility.ps1 -Mode ExportResults -OutputDirectory 'C:\Security\exports' -WhatIf

# All fourteen views; disabled/unconfigured optional views are recorded but not queried.
$report = .\Invoke-CloudAppVisibility.ps1 -Mode ExportResults `
    -ConfigPath $cfg -AccessToken $token -OutputDirectory 'C:\Security\exports'
$report | Select-Object Status, DashboardPath, ManifestPath

# Or export one view. -Confirm:$false is available for an approved unattended caller.
.\Invoke-CloudAppVisibility.ps1 -Mode ExportResults -QueryId operations `
    -ConfigPath $cfg -AccessToken $token -OutputDirectory 'C:\Security\exports'
```

Each run has a unique timestamp/GUID prefix and never overwrites another file. An all-view run produces 44 files, including status-only records for disabled optional views:

| Artifact | Contents |
|---|---|
| One `.csv` per view | All rows returned by the API, in schema column order; Excel-friendly tabular data. Nested values are compact JSON. |
| One `.json` per view | Unmodified returned values, schema, rendered query, collection times, status, configuration blockers and limit indicators. |
| One `.kql` per view | The exact rendered query for reproducibility and troubleshooting. Contains configured identifiers, not credentials. |
| `*-dashboard.html` | Self-contained report, summary cards and tables; no scripts, external fonts, remote assets or automatic uploads. Preview capped at 200 rows per view. |
| `*-manifest.json` | Tenant, collection interval, configured windows/counts/review flags, per-view status and returned row counts, completeness caveats, and absolute artifact paths. Written last. |

**An empty table is not a clean bill of health.** The report distinguishes:

- `ResultsReturned`: rows returned; this is not a malicious-activity verdict.
- `NoResults`: the configured query succeeded with zero returned rows.
- `NotConfigured`: prerequisite lists are empty; the query was not sent to Graph. Protected-access needs an account **or** resource list; the other contextual views require their cataloged lists.
- `QueryFailed`: the request failed, the API reported an error, or the response could not be validated. Other views continue. The run status becomes `CompletedWithQueryFailures`.

Successful empty views get CSV headers when a schema is available. Unconfigured/failed views without schema have empty CSV files; consult JSON and the manifest instead of interpreting an empty file as a successful query. If the API reports an error alongside rows, those rows remain explicitly flagged as potentially partial.

The results manifest is now **schema version 2**; consumers should check `SchemaVersion` before parsing. Per-view JSON, manifest entries and HTML include required tables, telemetry kind, visibility boundaries, native overlap, related-project ownership, and linked evidence classified by publication/modification date and observed-versus-lab status. `EvidenceAsOf` identifies the register date. Query success means only that the view ran—not that ingestion is complete. `QueryFailed` does not identify which dependency failed; use separate `Assess` probes. Exports reuse query outcomes rather than run extra health queries.

The manifest records optional-hunting flags, list counts, the configured activity window, the 30-day app-posture window, and the longer Teams alert context window. Views run sequentially using their existing relative query windows; collection is **not an atomic snapshot**. API row/time/resource limits and ingestion delays still apply. Warnings, continuation indicators and returned row counts at or above 100,000 are flagged, but absence of an indicator does not prove completeness. No pagination, automatic retry, time slicing or scheduled collection is introduced.

CSV quotes every field and prefixes formula-like values with an apostrophe, including values beginning with whitespace before `=`, `+`, `-` or `@`. JSON preserves the original values. HTML encodes result text and uses a restrictive content policy. These are safer handoff formats, not a substitute for treating exported evidence as untrusted data.

Exports contain sensitive identifiers and activity metadata. Keep them in an access-controlled location, apply your retention policy, and **do not commit them or a live tenant configuration to GitHub**. The package never uploads them. A filesystem failure stops the run and can leave already-written artifacts; a complete bundle requires a manifest and every file it lists. The manifest is an inventory, not a cryptographic attestation. This command is on demand, not a scheduler.

## Deploy only after tenant validation

There are two optional rules:

- **`cav-teams-endpoint-v1`:** reviewed native Teams alert + impacted Entra user + later endpoint tool execution. It uses **alert creation time**, not contact time; delayed alerts, missing user GUIDs, process activity under a different account, service-account execution and earlier executions can be missed. Correlation is not causation and does not prove a Tier-0 pivot.
- **`cav-watched-protected-access-v1`:** an explicitly watched app generates a reviewed operation on an explicitly protected ObjectId. This is business-context policy, not a new device-code/exfiltration detector. Only audited `Regular`/`Admin` account types with an impacted account GUID are included to avoid mapping service principals as user entities. App-only/system/unknown-account activity is excluded from this rule; use `app-timeline` and `protected-access` hunting to investigate it.

Both anchor `Timestamp` and `ReportId` to the original event. Endpoint correlation also preserves `DeviceId`/`DeviceName`. Detection event lookback is one hour; context lookback is two days. Late ingestion beyond that hour may be missed, and replay after ingestion/alert delays is not guaranteed. Do not assume this is NRT.

1. Assess data and connector coverage. Render queries and validate actual fields, operations, user mappings, results and false positives in your tenant.
2. Review native coverage and existing custom rules. Resolve duplication; set the applicable review flags in configuration.
3. Run an offline plan/WhatIf. `Deploy -WhatIf` makes **no network requests and no file writes**; it cannot establish live readiness.
4. Deploy **one selected rule** with explicit acknowledgement and an existing recovery directory:

```powershell
.\Invoke-CloudAppVisibility.ps1 -Mode Deploy -RuleId cav-teams-endpoint-v1 -ConfigPath $cfg -WhatIf

.\Invoke-CloudAppVisibility.ps1 -Mode Deploy -RuleId cav-teams-endpoint-v1 `
    -ConfigPath $cfg -AccessToken $token -OverlapReviewed -OutputDirectory 'C:\Security\recovery'
```

The deployer inventories custom rules, blocks exact-name/query conflicts under other IDs, compiles the actual detection query live and checks its output schema, asks for confirmation, saves a pre-change backup, and rechecks the target before writing. It reads back the result and requires disabled status. No automatic enabling or containment is offered. Empty query results can compile; compilation does not verify behavioral accuracy or sufficient coverage.

To update an existing **disabled, package-owned** rule, add `-UpdateExisting`. Ownership requires the stable catalog ID and description marker, not merely the display name. Do not rename stable IDs to make a display-name change. Enabled/auto-disabled rules or rules with automated actions are refused for manual review. The Graph v1.0 contract uses `status`, not deprecated `isEnabled`/`detectorId` properties.

After a benign, authorized end-to-end test and review in Defender, an operator may enable the rule manually. Existing Defender incident correlation is used; this package does not merge incidents or guarantee suppression of every native alert.

### Recovery and rollback

Each successful deployment produces a `*-before.json` backup and a `*-receipt.json` receipt. Keep both. The receipt records the prior writable definition and a fingerprint of the read-back state, without tokens.

```powershell
.\Invoke-CloudAppVisibility.ps1 -Mode Rollback -ConfigPath $cfg -AccessToken $token `
    -ReceiptPath 'C:\Security\recovery\<run>-receipt.json' -OutputDirectory 'C:\Security\recovery'
```

Rollback deletes a newly created rule or restores the previous disabled definition after an update. It refuses wrong-tenant receipts, changed definitions, non-owned rules, enabled rules and automated actions. Enabling/disabling or editing a rule after deployment can intentionally invalidate its receipt; review recovery manually rather than edit the receipt to defeat the guard.

Graph does not document an atomic conditional-write contract for these operations. Re-reading narrows, but cannot eliminate, a concurrent-edit race. Use a single operator/change window. If a request times out, a response is lost, read-back fails or receipt writing fails, **the tenant may already have changed**. Do not blindly retry. Inspect the stable rule ID and pre-change backup in Defender; recover manually if no completed receipt exists. No automatic compensating deletion is attempted after an ambiguous failure.

## Scope and limitations

- `OAuthAppInfo` is documented as preview, covers supported Microsoft 365-connected apps, and excludes Microsoft first-party apps and managed identities. Its metadata is not a complete Entra audit trail.
- Cloud Apps/app governance processing and hunting data can lag or differ. These queries do not assume all Graph calls, device-code events, app credentials, external app registrations or token issuance appear in `CloudAppEvents`.
- Existing native coverage includes credential-change/Graph sequences, dormant-app behavior, suspicious app downloads, inbox manipulation and other app anomalies. This package deliberately does not recreate those generically.
- No Entra audit/sign-in connector, Sentinel rule, endpoint deployment or AD lure is installed. No previously built AD code is copied into this empty project. Cross-domain alert context uses the existing alerts available in this tenant.
- No live tenant was contacted during package creation. Treat both rules as pilot candidates until validated locally.

## Validation

November 18 validation of the initial November 17 visibility update:

- **Passed:** all 23 offline Python contract tests (including application-identity boundaries, optional coverage/source classification, GitHub identifiers and results-export safety) and PowerShell syntax parsing of the module, launcher and mocked test suite. Detection definitions and their two KQL templates are unchanged from the published baseline.
- **Blocked:** execution of the mocked PowerShell suite because the unsigned scripts are blocked by this device's script-signing policy. Runtime deployment and rollback behavior remain unverified; sign the scripts and module through your trusted process before running the suite.
- **Not performed:** live KQL compilation, tenant assessment, detection deployment and end-to-end detection testing. These require authorized tenant configuration and access.

```powershell
python -B -m unittest discover -s tests -p 'test_static.py' -v
.\tests\Test-CloudAppVisibility.ps1
```

Python checks use only the standard library and make no network requests. They check package contracts and query invariants, **not KQL compilation**. The PowerShell suite imports the real module and mocks Graph; it tests plans, guards, payloads, export, assessment, deployment and rollback. It creates temporary records only inside `tests\output`, marks generated files, then removes its files. The runner refuses to use an existing output directory so it cannot delete another run's records. Device script-signing policy may block the suite until the scripts/module are signed through your trusted process. Live query compilation is performed only by online assessment/deployment in an authorized tenant.
