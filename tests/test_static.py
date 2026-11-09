"""Offline package-contract checks; these do not compile or execute KQL."""
import json
import re
import unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / "config.example.json").read_text(encoding="utf-8-sig"))
CATALOG = json.loads((ROOT / "catalog.json").read_text(encoding="utf-8-sig"))
EVIDENCE = json.loads((ROOT / "evidence.json").read_text(encoding="utf-8-sig"))
MODULE = (ROOT / "CloudAppVisibility.psm1").read_text(encoding="utf-8-sig")
TOKEN = re.compile(r"__([A-Za-z][A-Za-z0-9_]*)__")
QUERIES = {q["Id"]: (ROOT / "queries" / q["File"]).read_text(encoding="utf-8-sig") for q in CATALOG["Queries"]}


def render(text, detection=False, config=None):
    config = CONFIG if config is None else config
    replacements = {key: json.dumps(value) for key, value in config.items() if isinstance(value, list)}
    replacements.update(LOOKBACK="1h" if detection else "7d", CONTEXT_LOOKBACK="2d" if detection else "8d", SEQUENCE_WINDOW="120m")
    return TOKEN.sub(lambda match: replacements[match[1]], text)


def balanced(text):
    """Check delimiters outside JSON/KQL string literals and line comments."""
    stack = []
    pairs = {")": "(", "]": "[", "}": "{"}
    quote = None
    escaped = False
    for line in text.splitlines():
        index = 0
        while index < len(line):
            character = line[index]
            if quote:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == quote:
                    quote = None
            elif line[index:index + 2] == "//":
                break
            elif character in "\"'":
                quote = character
            elif character in "([{":
                stack.append(character)
            elif character in ")]}":
                if not stack or stack.pop() != pairs[character]:
                    return False
            index += 1
    return not stack and quote is None


class PackageContracts(unittest.TestCase):
    def test_catalog_ids_unique(self):
        for section in ("Queries", "Rules"):
            ids = [entry["Id"] for entry in CATALOG[section]]
            self.assertEqual(len(ids), len(set(ids)))

    def test_all_queries_cataloged(self):
        self.assertEqual({q["File"] for q in CATALOG["Queries"]}, {p.name for p in (ROOT / "queries").glob("*.kql")})

    def test_safe_query_paths(self):
        for query in CATALOG["Queries"]:
            self.assertRegex(query["File"], r"^\d{2}-[a-z-]+\.kql$")
            self.assertTrue(query["Tables"])

    def test_empty_tenant_sensitive_defaults(self):
        self.assertEqual("", CONFIG["TenantId"])
        for name in ("NativeTeamsAlertTitles", "ProtectedAccountObjectIds", "ProtectedResourceIds", "WatchedAppIds", "MonitoredActionTypes"):
            self.assertEqual([], CONFIG[name])
        self.assertFalse(any(CONFIG["Reviews"].values()))

    def test_tokens_known_and_rendered(self):
        for query in QUERIES.values():
            for detection in (False, True):
                rendered = render(query, detection)
                self.assertIsNone(TOKEN.search(rendered))
                self.assertTrue(balanced(rendered))

    def test_json_values_cannot_become_kql_operators(self):
        config = dict(CONFIG, ProtectedResourceIds=['a"); print injected=1; //', "quote' and \\ path"])
        query = render(QUERIES["protected-access"], config=config)
        line = next(line for line in query.splitlines() if line.startswith("let ProtectedResources"))
        data = line.split("dynamic(", 1)[1].removesuffix(");")
        self.assertEqual(config["ProtectedResourceIds"], json.loads(data))
        self.assertTrue(balanced(query))

    def test_rules_have_traceable_sources_and_guards(self):
        source_ids = {source["Id"] for source in EVIDENCE["Reports"]}
        for rule in CATALOG["Rules"]:
            self.assertIn(rule["QueryId"], QUERIES)
            self.assertTrue(set(rule["SourceIds"]) <= source_ids)
            self.assertIn(rule["ReviewFlag"], CONFIG["Reviews"])
            self.assertTrue(rule["RequiredLists"])
            self.assertGreater(len(rule["NativeOverlap"]), 50)
            self.assertTrue({"Timestamp", "ReportId", "AccountObjectId"} <= set(rule["RequiredColumns"]))

    def test_event_identifiers_retained(self):
        for rule in CATALOG["Rules"]:
            query = render(QUERIES[rule["QueryId"]], True)
            projection = query.rsplit("| project ", 1)[1].splitlines()[0]
            columns = {column.strip() for column in projection.split(",")}
            self.assertTrue(set(rule["RequiredColumns"]) <= columns)
            self.assertNotRegex(query, r"Timestamp\s*=\s*(now|ago)\(")
            self.assertIn("ago(1h)", query)

    def test_teams_join_is_impacted_guid_not_display_name(self):
        query = QUERIES["teams-endpoint"]
        self.assertIn('EvidenceRole =~ "Impacted"', query)
        self.assertIn("CorrelationAccountId=tolower(AccountObjectId)", query)
        self.assertIn("join kind=inner TeamsAlerts on CorrelationAccountId", query)
        self.assertIn("Timestamp >= AlertTimestamp", query)
        self.assertIn("by Timestamp, DeviceId, ReportId", query)
        self.assertNotIn("InitiatingProcessAccountObjectId", query)
        self.assertNotIn("AccountDisplayName", query)

    def test_protected_policy_requires_resource_app_and_operation(self):
        query = QUERIES["watched-protected-access"]
        for criterion in ("OAuthAppId in~ (WatchedApps)", "ObjectId in (ProtectedResources)", "ActionType in~ (ReviewedOperations)", "OAuthAppId !in~ (ApprovedApps)"):
            self.assertIn(criterion, query)

    def test_remediation_uses_event_time_and_latest_cutoff(self):
        query = QUERIES["remediation-review"]
        self.assertIn("RemediatedAt=max(RemediatedAt) by WatchedAppId", query)
        self.assertIn("Timestamp > RemediatedAt", query)
        self.assertNotIn("ingestion_time()", query)

    def test_latest_app_snapshot(self):
        self.assertIn("arg_max(Timestamp, *) by OAuthAppId", QUERIES["app-posture"])
        self.assertIn("ago(30d)", QUERIES["app-posture"])

    def test_no_unsafe_default_detail_exports(self):
        for query in QUERIES.values():
            self.assertNotIn("ProcessCommandLine", query)
            self.assertNotIn("RawEventData", query)
            self.assertNotIn("Subject", query)

    def test_source_dates_are_in_window_and_match_urls(self):
        start = date.fromisoformat(EVIDENCE["PublicationWindow"]["From"])
        end = date.fromisoformat(EVIDENCE["PublicationWindow"]["Through"])
        self.assertEqual(5, len(EVIDENCE["Reports"]))
        for source in EVIDENCE["Reports"]:
            published = date.fromisoformat(source["Published"])
            self.assertLessEqual(start, published)
            self.assertLessEqual(published, end)
            self.assertTrue(source["Url"].startswith("https://www.microsoft.com/en-us/security/blog/"))
            self.assertIn(published.strftime("/%Y/%m/%d/"), source["Url"])
            self.assertTrue(set(source["QueryIds"]) <= QUERIES.keys())
            for field in ("Attribution", "Observed", "Visibility", "NativeOverlap", "Enhancement"):
                self.assertGreater(len(source[field]), 20)

    def test_safe_deployment_contract(self):
        self.assertIn("status='disabled'", MODULE)
        self.assertIn("frequency='PT1H'", MODULE)
        self.assertNotIn("isEnabled=", MODULE)
        self.assertNotIn("detectorId=", MODULE)
        self.assertIn("Explicit OverlapReviewed acknowledgement is required", MODULE)
        self.assertIn("Only disabled managed rules can be updated", MODULE)
        self.assertIn("Test-CavLiveQuery $context $rule $AccessToken", MODULE)
        self.assertIn("[IO.FileMode]::CreateNew", MODULE)
        self.assertIn("PostFingerprint", MODULE)
        self.assertIn("$payload.Remove('id')", MODULE)
        self.assertIn("$target.Host -cne 'graph.microsoft.com'", MODULE)
        self.assertIn("MaximumRedirection=0", MODULE)

    def test_launcher_is_offline_by_default(self):
        launcher = (ROOT / "Invoke-CloudAppVisibility.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("[string]$Mode='Plan'", launcher)
        self.assertIn("Invoke-CavCommand @PSBoundParameters", launcher)

    def test_export_configuration_requirements(self):
        entries = {entry['Id']: entry for entry in CATALOG['Queries']}
        self.assertEqual(['ProtectedAccountObjectIds', 'ProtectedResourceIds'], entries['protected-access']['AnyConfiguredLists'])
        self.assertEqual(['RemediationRecords'], entries['remediation-review']['RequiredLists'])
        self.assertEqual(['NativeTeamsAlertTitles', 'RemoteToolFileNames'], entries['teams-endpoint']['RequiredLists'])
        for entry in entries.values():
            for key in ('RequiredLists', 'AnyConfiguredLists'):
                for name in entry.get(key, []):
                    self.assertIsInstance(CONFIG[name], list)
        for name in ('operations', 'app-posture', 'teams-alert-discovery'):
            self.assertNotIn('RequiredLists', entries[name])

    def test_results_export_contract(self):
        launcher = (ROOT / 'Invoke-CloudAppVisibility.ps1').read_text(encoding='utf-8-sig')
        self.assertIn("'ExportResults'", launcher)
        self.assertIn("'ExportResults'", MODULE)
        route = MODULE.split("if ($Mode -eq 'ExportResults') {", 1)[1].split("if ($Mode -in @('Deploy'", 1)[0]
        self.assertLess(route.index('$PSCmdlet.ShouldProcess'), route.index('Assert-CavToken'))
        exporter = MODULE.split('function Export-CavResults {', 1)[1].split('function Invoke-CavCommand {', 1)[0]
        self.assertNotIn('Invoke-CavGraph', exporter)
        for expected in ('NotConfigured', 'NoResults', 'ResultsReturned', 'QueryFailed', 'DashboardResultsManifest', 'NotGuaranteed', 'ConfiguredEntryCounts', '.csv', '.json', '.kql', '-dashboard.html', '-manifest.json'):
            self.assertIn(expected, exporter)
        self.assertIn('Get-CavExportBlockers $Context $entry', exporter)
        self.assertIn('Invoke-CavHunting -Query $query', exporter)
        self.assertIn('Get-CavZoneId $path', exporter)

    def test_portable_report_safety_contract(self):
        html = MODULE.split('function ConvertTo-CavHtml {', 1)[1].split('function Export-CavResults {', 1)[0]
        self.assertIn('[Net.WebUtility]::HtmlEncode', html)
        self.assertIn('Content-Security-Policy', html)
        self.assertIn("default-src 'none'", html)
        self.assertIn('Select-Object -First 200', html)
        self.assertNotIn('<script', html.lower())
        self.assertNotIn('src="https:', html.lower())
        csv = MODULE.split('function ConvertTo-CavCsvField {', 1)[1].split('function ConvertTo-CavHtml {', 1)[0]
        self.assertIn('[=+@-]', csv)
        self.assertIn('$text.Replace', csv)
        self.assertIn('ConvertTo-CavCsvField $column.name', csv)
        self.assertIn('$row.PSObject.Properties', csv)

    def test_module_does_not_weaken_device_protections(self):
        for prohibited in ("Unblock-File", "Set-ExecutionPolicy", "-ExecutionPolicy Bypass"):
            self.assertNotIn(prohibited, MODULE)
        self.assertIn("ZeroFreeBSTR", MODULE)
        self.assertIn("ZoneId=3", MODULE)


if __name__ == "__main__":
    unittest.main()
