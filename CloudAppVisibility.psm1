Set-StrictMode -Version Latest
$script:PackageRoot = $PSScriptRoot
$script:GraphRoot = 'https://graph.microsoft.com/v1.0'

function Get-CavZoneId {
    param([string]$Path)
    $args = @{ LiteralPath=$Path; Stream='Zone.Identifier'; TotalCount=65537; ErrorAction='Stop' }
    if ($PSVersionTable.PSVersion.Major -ge 6) { $args.AsByteStream=$true } else { $args.Encoding='Byte' }
    try { [byte[]]$bytes = @(Get-Content @args) }
    catch { if ($_.CategoryInfo.Category -eq 'ObjectNotFound') { return $null }; throw }
    if ($bytes.Length -gt 65536) { throw 'Zone.Identifier exceeds the safe read limit.' }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 255 -and $bytes[1] -eq 254) {
        $text = [Text.UnicodeEncoding]::new($false,$true,$true).GetString($bytes,2,$bytes.Length-2)
    } else { $text = [Text.UTF8Encoding]::new($false,$true).GetString($bytes,0,$bytes.Length) }
    $section = $false
    foreach ($line in ($text.Split([char]0)[0] -split "`n")) {
        $line=$line.Trim(" `t`r".ToCharArray())
        if ($line.StartsWith(';')) { continue }
        if ($line.StartsWith('[')) {
            if ($section) { return $null }
            $section=$line -match '^\[[ \t]*ZoneTransfer[ \t]*\]'
        } elseif ($section -and $line -match '^ZoneId[ \t]*=(.*)$') {
            $value=$Matches[1].Trim(" `t".ToCharArray())
            if ($value -match '^(?:"(.*)"|''(.*)'')$') {
                $value=if ($Matches.ContainsKey(1)) { $Matches[1] } else { $Matches[2] }
            }
            $value=$value.TrimStart([char[]](0..32)); $negative=$value.StartsWith('-')
            if ($negative -or $value.StartsWith('+')) { $value=$value.Substring(1) }
            $radix=10
            if ($value -cmatch '^0([xob])') { $radix=@{x=16;o=8;b=2}[$Matches[1]]; $value=$value.Substring(2) }
            [long]$zone=0; $digits=0
            foreach ($c in $value.ToCharArray()) {
                $digit='0123456789abcdef'.IndexOf([char]::ToLowerInvariant($c))
                if ($digit -lt 0 -or $digit -ge $radix) { break }
                $zone=($zone*$radix+$digit) -band 4294967295L; $digits++
            }
            if ($negative) { $zone=(4294967296L-$zone) -band 4294967295L }
            if ($digits -gt 0 -and $zone -le 4) { return $zone }; return $null
        }
    }
    return $null
}

function Write-CavFile {
    param([string]$Path, [string]$Text)
    $full=[IO.Path]::GetFullPath($Path)
    $parent=Split-Path -Parent $full
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw "Output directory must already exist: $parent" }
    $stream=[IO.File]::Open($full,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes($Text)
        $stream.Write($bytes,0,$bytes.Length)
    } finally { $stream.Dispose() }
    if ((Get-CavZoneId $full) -notin 3,4) {
        Set-Content -LiteralPath $full -Stream Zone.Identifier -Value '[ZoneTransfer]','ZoneId=3','HostUrl=about:internet' -ErrorAction Stop
    }
    if ((Get-CavZoneId $full) -notin 3,4) { throw "File security metadata verification failed: $full" }
    return $full
}

function ConvertFrom-CavJson {
    param([string]$Text)
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { return ConvertFrom-Json -InputObject $Text -DateKind String -ErrorAction Stop }
    return ConvertFrom-Json -InputObject $Text -ErrorAction Stop
}

function Read-CavContext {
    param([string]$ConfigPath)
    $config=ConvertFrom-CavJson (Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop)
    $example=ConvertFrom-CavJson (Get-Content -LiteralPath (Join-Path $script:PackageRoot 'config.example.json') -Raw)
    foreach ($property in $example.PSObject.Properties.Name) {
        if ($config.PSObject.Properties.Name -notcontains $property) { throw "Missing configuration property: $property" }
    }
    foreach ($property in $config.PSObject.Properties.Name) {
        if ($example.PSObject.Properties.Name -notcontains $property) { throw "Unknown configuration property: $property" }
    }
    if ($config.SchemaVersion -ne 1) { throw 'Unsupported configuration version.' }
    foreach ($range in @(@('LookbackDays',1,14),@('StaleAfterHours',1,720),@('SequenceWindowMinutes',1,240))) {
        $value=$config.($range[0])
        if ($value -isnot [int] -or $value -lt $range[1] -or $value -gt $range[2]) { throw "Invalid integer setting: $($range[0])" }
    }
    $guidFields=@('ProtectedAccountObjectIds','WatchedAppIds','ApprovedAppIds')
    $lists=@('NativeTeamsAlertTitles','RemoteToolFileNames','ApprovedSequenceDeviceIds','ProtectedAccountObjectIds','ProtectedResourceIds','WatchedAppIds','ApprovedAppIds','MonitoredActionTypes','RemediationRecords')
    foreach ($name in $lists) {
        if ($config.$name -isnot [array]) { throw "$name must be a JSON array." }
        if ($config.$name.Count -gt 500) { throw "$name exceeds the 500-entry limit." }
        if ($name -eq 'RemediationRecords') { continue }
        foreach ($value in $config.$name) {
            if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 2048 -or $value -match '[\x00-\x1f]') { throw "Invalid entry in $name" }
            if ($guidFields -contains $name -and $value -notmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$') { throw "$name requires canonical GUIDs." }
            if ($name -eq 'RemoteToolFileNames' -and $value -notmatch '^[\w .-]+\.exe$') { throw 'RemoteToolFileNames requires executable basenames, not paths or wildcards.' }
        }
    }
    if ($config.TenantId -isnot [string] -or ($config.TenantId -ne '' -and $config.TenantId -notmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$')) { throw 'TenantId must be empty for offline work or a canonical GUID.' }
    foreach ($name in @('NativeCoverageReviewed','TeamsAlertMappingsVerified','ProtectedAccessMappingsVerified')) {
        if ($config.Reviews.PSObject.Properties.Name -notcontains $name -or $config.Reviews.$name -isnot [bool]) { throw "Reviews.$name must be a JSON boolean." }
    }
    foreach ($app in $config.WatchedAppIds) {
        if ($config.ApprovedAppIds -contains $app) { throw 'An app cannot be both watched and approved.' }
    }
    foreach ($record in $config.RemediationRecords) {
        if ($record.PSObject.Properties.Name -notcontains 'OAuthAppId' -or $record.PSObject.Properties.Name -notcontains 'RemediatedAt') { throw 'Each remediation record requires OAuthAppId and RemediatedAt.' }
        if ($record.OAuthAppId -notmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$') { throw 'Invalid remediation app GUID.' }
        [DateTimeOffset]$date=[DateTimeOffset]::MinValue
        if ($record.RemediatedAt -isnot [string] -or $record.RemediatedAt -notmatch '^\d{4}-\d{2}-\d{2}T.*Z$' -or -not [DateTimeOffset]::TryParse($record.RemediatedAt,[ref]$date) -or $date -gt [DateTimeOffset]::UtcNow) { throw 'RemediatedAt must be a past ISO-8601 UTC timestamp ending in Z.' }
    }
    $catalog=Get-Content -LiteralPath (Join-Path $script:PackageRoot 'catalog.json') -Raw | ConvertFrom-Json
    return [pscustomobject]@{ Config=$config; Catalog=$catalog }
}

function Get-CavQuery {
    param($Context, [string]$QueryId, [switch]$ForDetection)
    $entries=@($Context.Catalog.Queries | Where-Object { $_.Id -ceq $QueryId })
    if ($entries.Count -ne 1) { throw "Unknown or duplicate query ID: $QueryId" }
    $file=$entries[0].File
    if ($file -notmatch '^[0-9]{2}-[a-z-]+\.kql$') { throw 'Invalid catalog query filename.' }
    $query=Get-Content -LiteralPath (Join-Path (Join-Path $script:PackageRoot 'queries') $file) -Raw -ErrorAction Stop
    $tokens=@{}
    foreach ($name in @('NativeTeamsAlertTitles','RemoteToolFileNames','ApprovedSequenceDeviceIds','ProtectedAccountObjectIds','ProtectedResourceIds','WatchedAppIds','ApprovedAppIds','MonitoredActionTypes','RemediationRecords')) {
        $tokens[$name]=ConvertTo-Json -InputObject @($Context.Config.$name) -Depth 12 -Compress
    }
    $tokens['LOOKBACK']=if ($ForDetection) { '1h' } else { "$($Context.Config.LookbackDays)d" }
    $tokens['CONTEXT_LOOKBACK']=if ($ForDetection) { '2d' } else { "$($Context.Config.LookbackDays+1)d" }
    $tokens['SEQUENCE_WINDOW']="$($Context.Config.SequenceWindowMinutes)m"
    $evaluator=[Text.RegularExpressions.MatchEvaluator]{ param($match)
        $key=$match.Groups[1].Value
        if (-not $tokens.ContainsKey($key)) { throw "Unknown KQL token: $key" }
        return $tokens[$key]
    }
    return [regex]::Replace($query,'__([A-Za-z][A-Za-z0-9_]*)__',$evaluator)
}

function Get-CavRule {
    param($Context, [string]$RuleId)
    $rules=@($Context.Catalog.Rules | Where-Object { $_.Id -ceq $RuleId })
    if ($rules.Count -ne 1) { throw "Unknown or duplicate rule ID: $RuleId" }
    return $rules[0]
}

function Get-CavReadiness {
    param($Context, $Rule)
    $reasons=@()
    if (-not $Context.Config.Reviews.NativeCoverageReviewed) { $reasons+='Native coverage review not acknowledged.' }
    if (-not $Context.Config.Reviews.($Rule.ReviewFlag)) { $reasons+="Review flag not set: $($Rule.ReviewFlag)" }
    foreach ($name in $Rule.RequiredLists) {
        if (@($Context.Config.$name).Count -eq 0) { $reasons+="Empty required list: $name" }
    }
    return $reasons
}

function Get-CavDefinition {
    param($Context, $Rule)
    $mappings=@{ accounts=@(@{ aadUserIdColumn='AccountObjectId' }) }
    $details=if ($Rule.HostMapping) { @{ SourceAlertId='SourceAlertId'; Tool='FileName'; SourceAlertTitle='SourceAlertTitle' } } else { @{ OAuthAppId='OAuthAppId'; ResourceId='ObjectId'; Operation='ActionType' } }
    if ($Rule.HostMapping) { $mappings['hosts']=@(@{ deviceIdColumn='DeviceId'; nameColumn='DeviceName' }) }
    return [ordered]@{
        id=$Rule.Id
        displayName=$Rule.Title
        description="[CloudAppVisibility:$($Rule.Id)] $($Rule.Description)"
        status='disabled'
        queryCondition=@{ queryText=(Get-CavQuery $Context $Rule.QueryId -ForDetection) }
        schedule=@{ frequency='PT1H' }
        detectionAction=@{ alertTemplate=@{
            title=$Rule.Title; description=$Rule.Description; severity=$Rule.Severity
            recommendedActions=$Rule.RecommendedActions; entityMappings=$mappings; customDetails=$details
        } }
    }
}

function Assert-CavToken {
    param([Security.SecureString]$AccessToken, [string]$TenantId)
    if ([string]::IsNullOrWhiteSpace($TenantId)) { throw 'Set TenantId before making tenant requests.' }
    if ($null -eq $AccessToken -or $AccessToken.Length -eq 0) { throw 'Supply a Microsoft Graph access token as a SecureString.' }
    $pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessToken)
    try {
        $plain=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        $parts=$plain.Split('.')
        if ($parts.Length -ne 3) { throw 'A tenant-bound Microsoft Graph JWT access token is required.' }
        $encoded=$parts[1].Replace('-','+').Replace('_','/')
        $encoded=$encoded.PadRight($encoded.Length+(4-$encoded.Length%4)%4,'=')
        try { $claims=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded)) | ConvertFrom-Json }
        catch { throw 'Unable to read access-token routing claims.' }
        if ($claims.tid -ine $TenantId) { throw 'Token tenant does not match configured TenantId.' }
        if ($claims.aud -notin @('https://graph.microsoft.com','https://graph.microsoft.com/','00000003-0000-0000-c000-000000000000')) { throw 'A Microsoft Graph audience token is required.' }
        $expiry=[DateTimeOffset]::FromUnixTimeSeconds([long]$claims.exp)
        if ($expiry -le [DateTimeOffset]::UtcNow.AddMinutes(2)) { throw 'Access token expires too soon or has expired.' }
    } finally { $plain=$null; [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

function Invoke-CavGraph {
    param([ValidateSet('GET','POST','PATCH','DELETE')][string]$Method, [string]$Uri, [Security.SecureString]$AccessToken, $Body)
    [uri]$target=$Uri
    if ($target.Scheme -cne 'https' -or $target.Host -cne 'graph.microsoft.com' -or $target.Port -ne 443 -or $target.UserInfo -ne '' -or $target.Fragment -ne '' -or $target.AbsolutePath -notmatch '^/v1\.0/security/(runHuntingQuery|rules/detectionRules(?:/[a-zA-Z0-9-]+)?)$') { throw 'Refusing an untrusted Graph URL.' }
    $pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessToken)
    $headers=$null
    try {
        $headers=@{ Authorization='Bearer '+[Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
        $args=@{ Uri=$Uri; Method=$Method; Headers=$headers; ErrorAction='Stop'; MaximumRedirection=0; TimeoutSec=180 }
        if ($null -ne $Body) { $args.Body=ConvertTo-Json -InputObject $Body -Depth 40 -Compress; $args.ContentType='application/json; charset=utf-8' }
        return Invoke-RestMethod @args
    } catch {
        $status='unknown'
        if ($_.Exception.PSObject.Properties.Name -contains 'Response' -and $null -ne $_.Exception.Response) { $status=[int]$_.Exception.Response.StatusCode }
        throw "Microsoft Graph request failed (HTTP $status). Verify permissions, tenant schema, API support and request validity. No automatic retry was made."
    } finally { if ($null -ne $headers) { $headers.Clear() }; [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

function Invoke-CavHunting {
    param([string]$Query, [Security.SecureString]$AccessToken)
    return Invoke-CavGraph -Method POST -Uri "$script:GraphRoot/security/runHuntingQuery" -AccessToken $AccessToken -Body @{ Query=$Query }
}

function Get-CavInventory {
    param([Security.SecureString]$AccessToken)
    $uri="$script:GraphRoot/security/rules/detectionRules"
    $seen=@{}; $items=@()
    while ($uri) {
        if ($seen.ContainsKey($uri) -or $seen.Count -ge 100) { throw 'Rule inventory pagination was incomplete or cyclic.' }
        $seen[$uri]=$true
        $page=Invoke-CavGraph -Method GET -Uri $uri -AccessToken $AccessToken
        if ($page.PSObject.Properties.Name -notcontains 'value') { throw 'Rule inventory response has no value collection.' }
        $items+=@($page.value)
        $uri=if ($page.PSObject.Properties.Name -contains '@odata.nextLink') { [string]$page.'@odata.nextLink' } else { $null }
    }
    return $items
}

function ConvertTo-CavCanonical {
    param($Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [Collections.IDictionary]) {
        $parts=@(foreach ($key in @($Value.Keys | Sort-Object -CaseSensitive)) { (ConvertTo-Json -InputObject ([string]$key) -Compress)+':'+(ConvertTo-CavCanonical $Value[$key]) })
        return '{'+($parts -join ',')+'}'
    }
    if ($Value -is [pscustomobject]) {
        $map=@{}; foreach ($property in $Value.PSObject.Properties) { $map[$property.Name]=$property.Value }
        return ConvertTo-CavCanonical $map
    }
    if ($Value -is [Collections.IEnumerable] -and $Value -isnot [string]) {
        $parts=@(foreach ($item in $Value) { ConvertTo-CavCanonical $item }); return '['+($parts -join ',')+']'
    }
    return ConvertTo-Json -InputObject $Value -Compress
}

function Get-CavWritable {
    param($Rule)
    $map=[ordered]@{}
    foreach ($name in @('id','displayName','description','status','detectionAction')) { $map[$name]=$Rule.$name }
    $map['queryCondition']=@{ queryText=$Rule.queryCondition.queryText }
    $map['schedule']=@{ frequency=$Rule.schedule.frequency }
    return $map
}

function Get-CavFingerprint {
    param($Rule)
    $canonical=ConvertTo-CavCanonical (Get-CavWritable $Rule)
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical)))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Assert-CavManaged {
    param($Existing, [string]$RuleId)
    if ($Existing.id -cne $RuleId -or -not ([string]$Existing.description).StartsWith("[CloudAppVisibility:$RuleId]",[StringComparison]::Ordinal)) { throw 'Refusing to modify a rule without the expected stable ID and ownership marker.' }
    if ($Existing.detectionAction.PSObject.Properties.Name -contains 'automatedActions' -and $null -ne $Existing.detectionAction.automatedActions) {
        foreach ($property in $Existing.detectionAction.automatedActions.PSObject.Properties) {
            if ($property.Name -notlike '@odata.*' -and $null -ne $property.Value -and @($property.Value).Count -gt 0) { throw 'Managed rule contains automated response actions; review it manually.' }
        }
    }
}

function Test-CavLiveQuery {
    param($Context, $Rule, [Security.SecureString]$AccessToken)
    $query=Get-CavQuery $Context $Rule.QueryId -ForDetection
    $response=Invoke-CavHunting -Query ($query+"`n| take 1") -AccessToken $AccessToken
    if ($response.PSObject.Properties.Name -notcontains 'schema') { throw 'Hunting response did not include a schema.' }
    $columns=@($response.schema | ForEach-Object { $_.name })
    foreach ($column in $Rule.RequiredColumns) { if ($columns -notcontains $column) { throw "Detection query is missing required output column: $column" } }
    return [pscustomobject]@{ RuleId=$Rule.Id; Status='QueryCompiled'; ReturnedSample=@($response.results).Count; Columns=$columns }
}

function Get-CavPlan {
    param($Context, [string]$RuleId)
    $rules=if ($RuleId) { @(Get-CavRule $Context $RuleId) } else { @($Context.Catalog.Rules) }
    return [pscustomobject]@{
        Mode='OfflinePlan'; TenantId=$Context.Config.TenantId; NetworkRequests=0
        NativePolicyAssessment='Manual review required; custom-rule inventory is not native policy inventory.'
        Rules=@(foreach ($rule in $rules) { [pscustomobject]@{
            Id=$rule.Id; Blockers=@(Get-CavReadiness $Context $rule); NativeOverlap=$rule.NativeOverlap
            SourceIds=$rule.SourceIds; Definition=(Get-CavDefinition $Context $rule)
        } })
    }
}

function Invoke-CavAssessment {
    param($Context, [Security.SecureString]$AccessToken, [switch]$IncludeRuleInventory)
    $tables=@('CloudAppEvents','OAuthAppInfo','AlertInfo','AlertEvidence','DeviceProcessEvents','IdentityLogonEvents')
    $health=@(foreach ($table in $tables) {
        try {
            $query="$table | where Timestamp > ago(30d) | summarize RowsInLookback=countif(Timestamp > ago($($Context.Config.LookbackDays)d)), LastSeen=max(Timestamp)"
            $response=Invoke-CavHunting -Query $query -AccessToken $AccessToken
            if (@($response.results).Count -ne 1) { throw 'Unexpected health query response.' }
            $row=$response.results[0]
            $status='NoRecentData'
            if ($row.LastSeen) {
                $age=([DateTimeOffset]::UtcNow-[DateTimeOffset]::Parse($row.LastSeen)).TotalHours
                $status=if ($table -eq 'OAuthAppInfo') { 'AvailableSnapshot' } elseif ($age -gt $Context.Config.StaleAfterHours) { 'StaleOrQuiet' } else { 'RecentData' }
            }
            [pscustomobject]@{ Table=$table; Status=$status; LastSeen=$row.LastSeen; RowsInLookback=$row.RowsInLookback; Error=$null }
        } catch { [pscustomobject]@{ Table=$table; Status='UnavailableOrQueryFailed'; LastSeen=$null; RowsInLookback=$null; Error=$_.Exception.Message } }
    })
    $checks=@(foreach ($entry in $Context.Catalog.Queries) {
        try {
            $response=Invoke-CavHunting -Query ((Get-CavQuery $Context $entry.Id)+"`n| take 1") -AccessToken $AccessToken
            [pscustomobject]@{ QueryId=$entry.Id; Status='Compiled'; ReturnedSample=@($response.results).Count; Error=$null }
        } catch { [pscustomobject]@{ QueryId=$entry.Id; Status='Failed'; ReturnedSample=$null; Error=$_.Exception.Message } }
    })
    $inventory=@(); $inventoryStatus='NotRequested'
    if ($IncludeRuleInventory) {
        try { $inventory=@(Get-CavInventory $AccessToken); $inventoryStatus='RetrievedCustomRulesOnly' }
        catch { $inventoryStatus=$_.Exception.Message }
    }
    $overlap=@(foreach ($rule in $Context.Catalog.Rules) {
        $desired=Get-CavDefinition $Context $rule
        foreach ($existing in $inventory) {
            if ($existing.id -ceq $rule.Id -or $existing.displayName -ieq $rule.Title -or $existing.queryCondition.queryText.Trim() -ceq $desired.queryCondition.queryText.Trim()) {
                [pscustomobject]@{ CandidateId=$rule.Id; ExistingId=$existing.id; ExistingName=$existing.displayName; StableIdMatch=($existing.id -ceq $rule.Id); Status=$existing.status }
            }
        }
    })
    return [pscustomobject]@{ Mode='ReadOnlyAssessment'; AssessedAt=[DateTimeOffset]::UtcNow.ToString('o'); TenantId=$Context.Config.TenantId; TableHealth=$health; QueryChecks=$checks; RuleInventoryStatus=$inventoryStatus; PossibleCustomRuleOverlap=$overlap; Readiness=(Get-CavPlan $Context '') }
}

function Get-CavExportBlockers {
    param($Context, $Entry)
    if ($Entry.PSObject.Properties.Name -contains 'RequiredLists') {
        foreach ($name in $Entry.RequiredLists) {
            if (@($Context.Config.$name).Count -eq 0) { "Empty required list: $name" }
        }
    }
    if ($Entry.PSObject.Properties.Name -contains 'AnyConfiguredLists') {
        $configured=@($Entry.AnyConfiguredLists | Where-Object { @($Context.Config.$_).Count -gt 0 })
        if ($configured.Count -eq 0) { 'Configure at least one of: '+($Entry.AnyConfiguredLists -join ', ') }
    }
}

function ConvertTo-CavCell {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [DateTime] -or $Value -is [DateTimeOffset]) { return $Value.ToString('o') }
    if ($Value -is [Collections.IDictionary] -or $Value -is [pscustomobject] -or ($Value -is [Collections.IEnumerable] -and $Value -isnot [string])) {
        return ConvertTo-Json -InputObject $Value -Depth 40 -Compress
    }
    if ($Value -is [IFormattable]) { return $Value.ToString($null,[Globalization.CultureInfo]::InvariantCulture) }
    return [string]$Value
}

function ConvertTo-CavCsvField {
    param($Value)
    $text=ConvertTo-CavCell $Value
    # Quoting alone does not stop spreadsheet formula execution.
    if ($text -match '^[\s\x00-\x20]*[=+@-]') { $text="'"+$text }
    return '"'+$text.Replace('"','""')+'"'
}

function ConvertTo-CavCsv {
    param([object[]]$Schema, [object[]]$Rows)
    if ($Schema.Count -eq 0) { return '' }
    $text=[Text.StringBuilder]::new()
    $header=@(foreach ($column in $Schema) { ConvertTo-CavCsvField $column.name })
    $null=$text.Append(($header -join ',')).Append("`r`n")
    foreach ($row in $Rows) {
        $fields=@(foreach ($column in $Schema) {
            $property=$row.PSObject.Properties[[string]$column.name]
            $value=if ($null -eq $property) { $null } else { $property.Value }
            ConvertTo-CavCsvField $value
        })
        $null=$text.Append(($fields -join ',')).Append("`r`n")
    }
    return $text.ToString()
}

function ConvertTo-CavHtml {
    param($Manifest, [object[]]$Views)
    $html=[Text.StringBuilder]::new()
    $null=$html.Append(@'
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Cloudy With a Chance of Tokens</title><style>
body{font:15px system-ui,sans-serif;background:#f4f6fa;color:#182238;max-width:1300px;margin:auto;padding:28px}h1{margin-bottom:4px}section,.card{background:white;border:1px solid #d9dfeb;border-radius:10px;padding:18px;margin:16px 0}.cards{display:flex;flex-wrap:wrap;gap:12px}.card{flex:1;min-width:130px}.card strong{display:block;font-size:24px}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;vertical-align:top;border-bottom:1px solid #d9dfeb;padding:8px;white-space:pre-wrap;overflow-wrap:anywhere;max-width:400px}th{background:#edf1f7}.notice{border-left:4px solid #5268b4;padding:12px;background:#e8edfa}code{overflow-wrap:anywhere}@media print{body{padding:0;background:white}.scroll{overflow:visible}section{break-inside:avoid}}
</style></head><body><h1>Cloudy With a Chance of Tokens</h1><p>Cloud app evidence. Fewer assumptions. Better handoffs.</p>
'@)
    $null=$html.Append('<p>Tenant: <code>').Append([Net.WebUtility]::HtmlEncode($Manifest.TenantId)).Append('</code><br>Collection: ')
    $null=$html.Append([Net.WebUtility]::HtmlEncode($Manifest.StartedAt)).Append(' to ').Append([Net.WebUtility]::HtmlEncode($Manifest.CompletedAt)).Append('</p>')
    $null=$html.Append('<p class="notice">Sensitive point-in-time report, not a live dashboard or a complete audit export. API limits and ingestion delays apply. Queries run sequentially with relative windows; this is not an atomic snapshot. HTML displays at most 200 returned rows per view; CSV and JSON contain all rows returned by the API.</p><div class="cards">')
    foreach ($status in @('ResultsReturned','NoResults','NotConfigured','QueryFailed')) {
        $count=@($Views | Where-Object { $_.Status -eq $status }).Count
        $null=$html.Append('<div class="card"><strong>').Append($count).Append('</strong>').Append($status).Append('</div>')
    }
    $null=$html.Append('</div>')
    foreach ($view in $Views) {
        $null=$html.Append('<section><h2>').Append([Net.WebUtility]::HtmlEncode($view.Title)).Append('</h2><p><code>')
        $null=$html.Append([Net.WebUtility]::HtmlEncode($view.QueryId)).Append('</code> | ').Append($view.Status).Append(' | Returned rows: ').Append($view.RowCount).Append('</p>')
        foreach ($message in @($view.Blockers)+@($view.Error)+@($view.LimitIndicators)) {
            if ($message) { $null=$html.Append('<p>').Append([Net.WebUtility]::HtmlEncode([string]$message)).Append('</p>') }
        }
        if ($view.Schema.Count -gt 0) {
            $null=$html.Append('<div class="scroll"><table><thead><tr>')
            foreach ($column in $view.Schema) { $null=$html.Append('<th>').Append([Net.WebUtility]::HtmlEncode([string]$column.name)).Append('</th>') }
            $null=$html.Append('</tr></thead><tbody>')
            foreach ($row in @($view.Results | Select-Object -First 200)) {
                $null=$html.Append('<tr>')
                foreach ($column in $view.Schema) {
                    $property=$row.PSObject.Properties[[string]$column.name]
                    $value=if ($null -eq $property) { $null } else { $property.Value }
                    $null=$html.Append('<td>').Append([Net.WebUtility]::HtmlEncode((ConvertTo-CavCell $value))).Append('</td>')
                }
                $null=$html.Append('</tr>')
            }
            $null=$html.Append('</tbody></table></div>')
            if ($view.RowCount -gt 200) { $null=$html.Append('<p>HTML preview limited to 200 rows. See CSV/JSON for all returned rows.</p>') }
        }
        $null=$html.Append('</section>')
    }
    $null=$html.Append('</body></html>')
    return $html.ToString()
}

function Export-CavResults {
    param($Context, [Security.SecureString]$AccessToken, [string]$OutputDirectory, [string]$QueryId)
    $entries=@($Context.Catalog.Queries)
    if ($QueryId) {
        $entries=@($entries | Where-Object { $_.Id -ceq $QueryId })
        if ($entries.Count -ne 1) { throw "Unknown or duplicate query ID: $QueryId" }
    }
    $directory=[IO.Path]::GetFullPath($OutputDirectory)
    $before=@(Get-ChildItem -LiteralPath $directory -Force -File | Select-Object -ExpandProperty FullName)
    $runId=[DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[guid]::NewGuid().ToString('N')
    $started=[DateTimeOffset]::UtcNow.ToString('o'); $views=@(); $files=@()
    foreach ($entry in $entries) {
        $query=Get-CavQuery $Context $entry.Id
        $blockers=@(Get-CavExportBlockers $Context $entry)
        $view=[pscustomobject][ordered]@{
            QueryId=$entry.Id; Title=$entry.Title; Tables=@($entry.Tables); Status='NotConfigured'
            StartedAt=$null; CompletedAt=$null; Blockers=$blockers; Error=$null
            QueryText=$query; Schema=@(); Results=@(); RowCount=0
            Completeness='NotGuaranteed'; LimitIndicators=@()
        }
        if ($blockers.Count -eq 0) {
            $view.StartedAt=[DateTimeOffset]::UtcNow.ToString('o')
            try {
                $response=Invoke-CavHunting -Query $query -AccessToken $AccessToken
                if ($null -eq $response -or $response.PSObject.Properties.Name -notcontains 'schema' -or $response.PSObject.Properties.Name -notcontains 'results') { throw 'Missing hunting response collections.' }
                if ($response.schema -isnot [array] -or $response.results -isnot [array]) { throw 'Invalid hunting response collections.' }
                $names=@()
                foreach ($column in $response.schema) {
                    if ($null -eq $column -or $column.PSObject.Properties.Name -notcontains 'name' -or [string]::IsNullOrWhiteSpace([string]$column.name) -or $names -contains [string]$column.name) { throw 'Invalid or duplicate result column.' }
                    $names+=([string]$column.name)
                }
                if (@($response.results).Count -gt 0 -and $names.Count -eq 0) { throw 'Result rows have no schema.' }
                foreach ($row in $response.results) { if ($row -isnot [pscustomobject]) { throw 'Unexpected result row type.' } }
                $view.Schema=@($response.schema); $view.Results=@($response.results); $view.RowCount=$view.Results.Count
                $view.Status=if ($view.RowCount -eq 0) { 'NoResults' } else { 'ResultsReturned' }
                if ($view.RowCount -ge 100000) { $view.LimitIndicators+='Row count at or above 100000; possible API row limit.' }
                foreach ($name in @('@odata.nextLink','warnings','errors','error')) {
                    if ($response.PSObject.Properties.Name -contains $name -and $response.$name) { $view.LimitIndicators+="API returned ${name}; result completeness requires review in Advanced Hunting." }
                }
                if (@($view.LimitIndicators | Where-Object { $_ -like 'API returned error*' }).Count -gt 0) {
                    $view.Status='QueryFailed'; $view.Error='The API reported an error; any returned rows may be partial.'
                }
            } catch { $view.Status='QueryFailed'; $view.Error='Query request or response validation failed. Check tenant permissions, table availability and the rendered query in Advanced Hunting.' }
            $view.CompletedAt=[DateTimeOffset]::UtcNow.ToString('o')
        }
        $base=Join-Path $directory "$runId-$($entry.Id)"
        $files+=Write-CavFile -Path "$base.kql" -Text $query
        $files+=Write-CavFile -Path "$base.json" -Text (ConvertTo-Json -InputObject $view -Depth 40)
        $files+=Write-CavFile -Path "$base.csv" -Text (ConvertTo-CavCsv -Schema $view.Schema -Rows $view.Results)
        $views+=$view
    }
    $manifest=[ordered]@{
        SchemaVersion=1; Kind='DashboardResultsManifest'; RunId=$runId; TenantId=$Context.Config.TenantId
        StartedAt=$started; CompletedAt=[DateTimeOffset]::UtcNow.ToString('o'); Mode='ReadOnlyResultsExport'
        Status=if (@($views | Where-Object { $_.Status -eq 'QueryFailed' }).Count -gt 0) { 'CompletedWithQueryFailures' } elseif (@($views | Where-Object { $_.Status -eq 'NotConfigured' }).Count -gt 0) { 'CompletedWithUnconfiguredViews' } else { 'Completed' }
        Context=@{
            LookbackDays=$Context.Config.LookbackDays; AppPostureLookbackDays=30
            TeamsContextLookbackDays=($Context.Config.LookbackDays+1); SequenceWindowMinutes=$Context.Config.SequenceWindowMinutes
            ConfiguredEntryCounts=@{}; Reviews=$Context.Config.Reviews
        }
        Completeness='Not guaranteed: API row/time/resource limits, sequential relative query windows and ingestion delays apply. No paging, retries or audit completeness guarantee.'
        CsvPolicy='All fields quoted; formula-like cells prefixed with apostrophe. JSON preserves unmodified returned values. Nested cells are compact JSON.'
        HtmlPreviewRowsPerView=200; Views=@(); Files=@()
    }
    foreach ($name in @('NativeTeamsAlertTitles','RemoteToolFileNames','ApprovedSequenceDeviceIds','ProtectedAccountObjectIds','ProtectedResourceIds','WatchedAppIds','ApprovedAppIds','MonitoredActionTypes','RemediationRecords')) { $manifest.Context.ConfiguredEntryCounts[$name]=@($Context.Config.$name).Count }
    $manifest.Views=@($views | Select-Object QueryId,Title,Status,StartedAt,CompletedAt,RowCount,Blockers,Error,Completeness,LimitIndicators)
    $htmlPath=Join-Path $directory "$runId-dashboard.html"; $manifestPath=Join-Path $directory "$runId-manifest.json"
    $manifest.Files=@($files)+@($htmlPath,$manifestPath)
    $null=Write-CavFile -Path $htmlPath -Text (ConvertTo-CavHtml -Manifest $manifest -Views $views)
    $null=Write-CavFile -Path $manifestPath -Text (ConvertTo-Json -InputObject $manifest -Depth 40)
    $after=@(Get-ChildItem -LiteralPath $directory -Force -File | Select-Object -ExpandProperty FullName)
    foreach ($path in $manifest.Files) {
        if ($before -contains $path -or $after -notcontains $path -or (Get-CavZoneId $path) -notin 3,4) { throw 'Export inventory verification failed.' }
    }
    return [pscustomobject]@{ Mode='ExportResults'; Status=$manifest.Status; RunId=$runId; DashboardPath=$htmlPath; ManifestPath=$manifestPath; Files=$manifest.Files; Views=$manifest.Views }
}

function Invoke-CavCommand {
    [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
    param(
        [ValidateSet('Plan','Export','ExportResults','Assess','Hunt','Deploy','Rollback')][string]$Mode='Plan',
        [string]$ConfigPath=(Join-Path $script:PackageRoot 'config.example.json'),
        [Security.SecureString]$AccessToken,
        [string]$QueryId,
        [string]$RuleId,
        [string]$OutputDirectory,
        [string]$ReceiptPath,
        [switch]$IncludeRuleInventory,
        [switch]$OverlapReviewed,
        [switch]$UpdateExisting
    )
    $context=Read-CavContext $ConfigPath
    if ($Mode -eq 'Plan') { return Get-CavPlan $context $RuleId }
    if ($Mode -eq 'Export') {
        if (-not $OutputDirectory -or -not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) { throw 'Export requires an existing OutputDirectory.' }
        if (-not $PSCmdlet.ShouldProcess($OutputDirectory,'Export configured hunting queries and disabled rule definitions')) { return }
        $runId=[guid]::NewGuid().ToString('N')
        foreach ($entry in $context.Catalog.Queries) {
            Write-CavFile -Path (Join-Path $OutputDirectory "$runId-$($entry.Id).kql") -Text (Get-CavQuery $context $entry.Id)
        }
        return Write-CavFile -Path (Join-Path $OutputDirectory "$runId-plan.json") -Text ((Get-CavPlan $context $RuleId) | ConvertTo-Json -Depth 40)
    }
    if ($Mode -eq 'ExportResults') {
        if (-not $OutputDirectory -or -not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) { throw 'ExportResults requires an existing OutputDirectory.' }
        if (-not $PSCmdlet.ShouldProcess($OutputDirectory,'Run read-only hunting queries and save sensitive CSV, JSON and HTML results')) { return }
        Assert-CavToken $AccessToken $context.Config.TenantId
        return Export-CavResults -Context $context -AccessToken $AccessToken -OutputDirectory $OutputDirectory -QueryId $QueryId
    }
    if ($Mode -in @('Deploy','Rollback') -and $WhatIfPreference) { return Get-CavPlan $context $RuleId }
    Assert-CavToken $AccessToken $context.Config.TenantId
    if ($Mode -eq 'Assess') {
        $report=Invoke-CavAssessment $context $AccessToken -IncludeRuleInventory:$IncludeRuleInventory
        if ($OutputDirectory) { $null=Write-CavFile -Path (Join-Path $OutputDirectory (([guid]::NewGuid().ToString('N'))+'-assessment.json')) -Text ($report | ConvertTo-Json -Depth 40) }
        return $report
    }
    if ($Mode -eq 'Hunt') {
        if (-not $QueryId) { throw 'Hunt requires QueryId.' }
        return Invoke-CavHunting -Query (Get-CavQuery $context $QueryId) -AccessToken $AccessToken
    }
    if (-not $OutputDirectory -or -not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) { throw 'Deployment and rollback require an existing OutputDirectory for recovery records.' }
    $inventory=@(Get-CavInventory $AccessToken)
    $previous=$null; $receipt=$null
    if ($Mode -eq 'Deploy') {
        $rule=Get-CavRule $context $RuleId
        $reasons=@(Get-CavReadiness $context $rule)
        if ($reasons.Count -gt 0) { throw ($reasons -join ' ') }
        if (-not $OverlapReviewed) { throw 'Explicit OverlapReviewed acknowledgement is required; exact matching cannot establish semantic uniqueness.' }
        $desired=Get-CavDefinition $context $rule
        $existing=@($inventory | Where-Object { $_.id -ceq $RuleId })
        if ($existing.Count -gt 1) { throw 'Duplicate stable rule IDs in inventory.' }
        if ($existing.Count -eq 1) {
            $previous=$existing[0]; Assert-CavManaged $previous $RuleId
            if (-not $UpdateExisting) { throw 'Rule already exists. Use UpdateExisting after reviewing the plan.' }
            if ($previous.status -cne 'disabled') { throw 'Only disabled managed rules can be updated. Disable and review the rule in Defender first.' }
        }
        foreach ($other in $inventory) {
            if ($other.id -ceq $RuleId) { continue }
            if ($other.displayName -ieq $rule.Title -or $other.queryCondition.queryText.Trim() -ceq $desired.queryCondition.queryText.Trim()) { throw "Possible duplicate custom rule: $($other.id). Resolve overlap before deployment." }
        }
        $null=Test-CavLiveQuery $context $rule $AccessToken
        if (-not $PSCmdlet.ShouldProcess("$($context.Config.TenantId)/$RuleId",'Create or update a DISABLED detection with no automated actions')) { return }
        $operation=if ($null -eq $previous) { 'Create' } else { 'Update' }
    } else {
        if (-not $ReceiptPath) { throw 'Rollback requires the receipt produced by a completed deployment.' }
        $receipt=ConvertFrom-CavJson (Get-Content -LiteralPath $ReceiptPath -Raw -ErrorAction Stop)
        if ($receipt.SchemaVersion -ne 1 -or $receipt.Kind -cne 'DeploymentReceipt' -or $receipt.TenantId -ine $context.Config.TenantId -or $receipt.Operation -notin @('Create','Update')) { throw 'Invalid or wrong-tenant deployment receipt.' }
        $RuleId=$receipt.RuleId; $null=Get-CavRule $context $RuleId
        $matches=@($inventory | Where-Object { $_.id -ceq $RuleId })
        if ($matches.Count -ne 1) { throw 'Rollback target was not found uniquely.' }
        $previous=$matches[0]; Assert-CavManaged $previous $RuleId
        if ((Get-CavFingerprint $previous) -cne $receipt.PostFingerprint) { throw 'Rule changed since deployment. Refusing to overwrite or delete concurrent changes.' }
        if ($previous.status -cne 'disabled') { throw 'Rollback only operates on disabled rules. Disable and review the rule in Defender first.' }
        if ($receipt.Operation -eq 'Update') {
            Assert-CavManaged $receipt.PreviousDefinition $RuleId
            if ($receipt.PreviousDefinition.status -cne 'disabled') { throw 'Receipt would restore an enabled rule; refusing.' }
        }
        if (-not $PSCmdlet.ShouldProcess("$($context.Config.TenantId)/$RuleId",'Roll back an unchanged disabled managed rule')) { return }
        $operation='Rollback'
    }
    $runId=[guid]::NewGuid().ToString('N')
    $before=if ($null -eq $previous) { $null } else { Get-CavWritable $previous }
    $record=[ordered]@{ SchemaVersion=1; Kind='PreChangeBackup'; TenantId=$context.Config.TenantId; RuleId=$RuleId; Operation=$operation; RecordedAt=[DateTimeOffset]::UtcNow.ToString('o'); PreviousDefinition=$before }
    $backup=Write-CavFile -Path (Join-Path $OutputDirectory "$runId-before.json") -Text ($record | ConvertTo-Json -Depth 40)
    $uri="$script:GraphRoot/security/rules/detectionRules/$RuleId"
    # Re-read after confirmation and backup to narrow the read/write race; Graph exposes no conditional-write contract here.
    $fresh=@(Get-CavInventory $AccessToken | Where-Object { $_.id -ceq $RuleId })
    if ($null -eq $previous) {
        if ($fresh.Count -ne 0) { throw 'Rule appeared during preflight; no tenant changes made.' }
    } elseif ($fresh.Count -ne 1 -or (Get-CavFingerprint $fresh[0]) -cne (Get-CavFingerprint $previous)) { throw 'Rule changed during preflight; no tenant changes made.' }
    try {
        if ($Mode -eq 'Deploy') {
            $payload=@{}; foreach ($key in $desired.Keys) { $payload[$key]=$desired[$key] }
            if ($operation -eq 'Create') { $null=Invoke-CavGraph -Method POST -Uri "$script:GraphRoot/security/rules/detectionRules" -AccessToken $AccessToken -Body $payload }
            else { $payload.Remove('id'); $null=Invoke-CavGraph -Method PATCH -Uri $uri -AccessToken $AccessToken -Body $payload }
            $post=Invoke-CavGraph -Method GET -Uri $uri -AccessToken $AccessToken
            Assert-CavManaged $post $RuleId
            if ($post.status -cne 'disabled') { throw 'Post-deployment status was not disabled.' }
            $result=[ordered]@{ SchemaVersion=1; Kind='DeploymentReceipt'; TenantId=$context.Config.TenantId; RuleId=$RuleId; Operation=$operation; RecordedAt=[DateTimeOffset]::UtcNow.ToString('o'); PreviousDefinition=$before; PostFingerprint=(Get-CavFingerprint $post); BackupPath=$backup }
        } else {
            if ($receipt.Operation -eq 'Create') {
                $null=Invoke-CavGraph -Method DELETE -Uri $uri -AccessToken $AccessToken
                $remaining=@(Get-CavInventory $AccessToken | Where-Object { $_.id -ceq $RuleId })
                if ($remaining.Count -ne 0) { throw 'Rollback deletion was not verified.' }
            } else {
                $payload=Get-CavWritable $receipt.PreviousDefinition; $payload.Remove('id')
                $null=Invoke-CavGraph -Method PATCH -Uri $uri -AccessToken $AccessToken -Body $payload
                $restored=Invoke-CavGraph -Method GET -Uri $uri -AccessToken $AccessToken
                if ((Get-CavFingerprint $restored) -cne (Get-CavFingerprint $receipt.PreviousDefinition)) { throw 'Restored definition did not match the receipt.' }
            }
            $result=[ordered]@{ SchemaVersion=1; Kind='RollbackReceipt'; TenantId=$context.Config.TenantId; RuleId=$RuleId; RecordedAt=[DateTimeOffset]::UtcNow.ToString('o'); BackupPath=$backup; Status='Verified' }
        }
        $path=Write-CavFile -Path (Join-Path $OutputDirectory "$runId-receipt.json") -Text ($result | ConvertTo-Json -Depth 40)
        return [pscustomobject]@{ Mode=$Mode; RuleId=$RuleId; Status='Verified'; ReceiptPath=$path; BackupPath=$backup }
    } catch { throw "Operation did not finish cleanly; the tenant may have changed. Recovery backup: $backup. Inspect the live rule before retrying. $($_.Exception.Message)" }
}

Export-ModuleMember -Function Invoke-CavCommand
