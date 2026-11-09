#Requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$output=Join-Path $PSScriptRoot 'output'
if (Test-Path -LiteralPath $output) { throw 'tests\output already exists; refusing to use or delete an existing directory.' }
Import-Module (Join-Path $root 'CloudAppVisibility.psm1') -Force -ErrorAction Stop
$module=Get-Module CloudAppVisibility
$null=New-Item -ItemType Directory -Path $output -ErrorAction Stop
try {
    & $module {
        param($OutputPath)
        $script:Checks=0
        function Assert-Test([bool]$Condition,[string]$Message) {
            if (-not $Condition) { throw "FAILED: $Message" }
            $script:Checks++
        }
        function Assert-Throws([scriptblock]$Action,[string]$Pattern) {
            $caught=$false
            try { $null=& $Action } catch { $caught=$true; if ($_.Exception.Message -notmatch $Pattern) { throw "Unexpected failure: $($_.Exception.Message)" } }
            Assert-Test $caught "Expected failure matching $Pattern"
        }
        function Clone-Test($Value) { ConvertFrom-CavJson (ConvertTo-Json -InputObject $Value -Depth 40) }
        $context=Read-CavContext (Join-Path $script:PackageRoot 'config.example.json')
        Assert-Test (@($context.Catalog.Queries).Count -eq 9) 'Nine hunting queries'
        $plan=Get-CavPlan $context ''
        Assert-Test ($plan.NetworkRequests -eq 0) 'Offline plan'
        foreach ($rule in $plan.Rules) {
            Assert-Test ($rule.Definition.status -ceq 'disabled') 'Disabled definition'
            Assert-Test (@($rule.Blockers).Count -gt 0) 'Empty configuration blocks deployment'
            Assert-Test ($null -eq $rule.Definition.detectionAction['automatedActions']) 'No automated action payload'
        }
        foreach ($entry in $context.Catalog.Queries) {
            $query=Get-CavQuery $context $entry.Id
            Assert-Test ($query -notmatch '__[A-Za-z][A-Za-z0-9_]*__') "All tokens rendered: $($entry.Id)"
        }
        $context.Config.ProtectedResourceIds=@('quote"; print bad=1; //')
        $rendered=Get-CavQuery $context 'protected-access'
        Assert-Test ($rendered.Contains('\"; print bad=1; //')) 'Resource values are JSON-escaped'
        $context.Config.ProtectedResourceIds=@()
        Assert-Throws { Get-CavQuery $context '..\outside' } 'Unknown'
        Assert-Throws { Get-CavRule $context 'not-a-rule' } 'Unknown'

        $bad=Clone-Test $context.Config; $bad.LookbackDays=0
        $badPath=Write-CavFile (Join-Path $OutputPath 'invalid-config.json') ($bad | ConvertTo-Json -Depth 15)
        Assert-Throws { Read-CavContext $badPath } 'Invalid integer'
        Assert-Throws { Write-CavFile $badPath 'must not overwrite' } 'exist'
        Assert-Test ((Get-CavZoneId $badPath) -in 3,4) 'Generated file carries verified metadata'

        $tenant='11111111-1111-4111-8111-111111111111'
        $account='22222222-2222-4222-8222-222222222222'
        $app='33333333-3333-4333-8333-333333333333'
        $context.Config.TenantId=$tenant
        $context.Config.ProtectedAccountObjectIds=@($account)
        $context.Config.WatchedAppIds=@($app)
        $context.Config.ProtectedResourceIds=@('actual-audit-object-id')
        $context.Config.MonitoredActionTypes=@('ReviewedReadOperation')
        $context.Config.NativeTeamsAlertTitles=@('Reviewed native Teams test alert')
        $context.Config.Reviews.NativeCoverageReviewed=$true
        $context.Config.Reviews.TeamsAlertMappingsVerified=$true
        $context.Config.Reviews.ProtectedAccessMappingsVerified=$true
        $tokenData=@{ tid=$tenant; aud='00000003-0000-0000-c000-000000000000'; exp=[DateTimeOffset]::UtcNow.AddHours(1).ToUnixTimeSeconds() } | ConvertTo-Json -Compress
        $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($tokenData)).TrimEnd('=').Replace('+','-').Replace('/','_')
        $token=ConvertTo-SecureString -String ('fixture.'+$encoded+'.not-a-signature') -AsPlainText -Force
        Assert-CavToken $token $tenant
        Assert-Throws { Assert-CavToken $token $account } 'tenant'
        Assert-Throws { Invoke-CavGraph GET 'https://example.invalid/v1.0/security/rules/detectionRules' $token } 'untrusted'
        Assert-Throws { Invoke-CavGraph GET 'https://graph.microsoft.com/v1.0/users' $token } 'untrusted'
        $configPath=Write-CavFile (Join-Path $OutputPath 'tenant-fixture.json') ($context.Config | ConvertTo-Json -Depth 15)

        $script:Store=@{}; $script:Requests=0; $script:Writes=0; $script:FailReadback=$false; $script:FailHealth=$false
        $script:ExportFixture=$false; $script:MalformedExport=$false
        function script:Invoke-CavGraph {
            param([string]$Method,[string]$Uri,[Security.SecureString]$AccessToken,$Body)
            $script:Requests++
            if ($Uri.EndsWith('/runHuntingQuery')) {
                if ($script:MalformedExport) { return [pscustomobject]@{ results=@() } }
                if ($script:ExportFixture) {
                    if ($Body.Query -match '^OAuthAppInfo') { throw 'Fixture: app metadata unavailable' }
                    if ($Body.Query -match '^CloudAppEvents' -and $Body.Query -match 'WithOAuthAppId=countif') {
                        return [pscustomobject]@{
                            schema=@('Value','Payload','Nested' | ForEach-Object { [pscustomobject]@{ name=$_; type='String' } })
                            results=@(1..201 | ForEach-Object { [pscustomobject]@{ Value=' =1+1'; Payload='</td><script>alert(1)</script>'; Nested=@{ labels=@('one','two') } } })
                            warnings=@('Fixture: possible partial result')
                        }
                    }
                }
                if ($Body.Query -match '^IdentityLogonEvents' -and $script:FailHealth) { throw 'Fixture: optional table unavailable' }
                if ($Body.Query -match 'RowsInLookback=countif') {
                    return [pscustomobject]@{ schema=@(); results=@([pscustomobject]@{ RowsInLookback=1; LastSeen=[DateTimeOffset]::UtcNow.ToString('o') }) }
                }
                return [pscustomobject]@{
                    schema=@('Timestamp','ReportId','DeviceId','DeviceName','AccountObjectId' | ForEach-Object { [pscustomobject]@{ name=$_; type='String' } })
                    results=@()
                }
            }
            $id=($Uri -split '/')[-1]
            if ($Method -eq 'GET' -and $id -eq 'detectionRules') { return [pscustomobject]@{ value=@($script:Store.Values) } }
            if ($Method -eq 'GET') {
                if ($script:FailReadback) { $script:FailReadback=$false; throw 'Fixture: read-back failed after write' }
                return $script:Store[$id]
            }
            $script:Writes++
            if ($Method -eq 'POST') {
                if ($script:Store.ContainsKey($Body.id)) { throw 'Fixture: duplicate ID' }
                $created=ConvertFrom-CavJson (ConvertTo-Json -InputObject $Body -Depth 40)
                $created.schedule | Add-Member -NotePropertyName nextRunDateTime -NotePropertyValue '2099-01-01T00:00:00Z'
                $script:Store[$Body.id]=$created
                return $created
            }
            if ($Method -eq 'PATCH') {
                foreach ($key in $Body.Keys) { $script:Store[$id] | Add-Member -NotePropertyName $key -NotePropertyValue (Clone-Test $Body[$key]) -Force }
                return $script:Store[$id]
            }
            if ($Method -eq 'DELETE') { $script:Store.Remove($id); return }
            throw 'Unexpected mocked request'
        }

        $beforeRequests=$script:Requests
        $null=Invoke-CavCommand -Mode Deploy -RuleId cav-teams-endpoint-v1 -ConfigPath $configPath -WhatIf
        Assert-Test ($script:Requests -eq $beforeRequests) 'WhatIf makes no Graph requests'
        $exports=@(Invoke-CavCommand -Mode Export -ConfigPath $configPath -OutputDirectory $OutputPath -Confirm:$false)
        Assert-Test ($exports.Count -eq 10) 'Nine configured views and one plan exported'
        foreach ($path in $exports) { Assert-Test ((Get-CavZoneId $path) -in 3,4) 'Export metadata verified' }
        $script:FailHealth=$true
        $assessment=Invoke-CavCommand -Mode Assess -ConfigPath $configPath -AccessToken $token -IncludeRuleInventory
        Assert-Test (@($assessment.TableHealth | Where-Object { $_.Status -eq 'UnavailableOrQueryFailed' }).Count -eq 1) 'Unavailable optional table is isolated'
        Assert-Test (@($assessment.QueryChecks | Where-Object { $_.Status -eq 'Compiled' }).Count -eq 9) 'Other queries still compile'
        Assert-Test ($script:Writes -eq 0) 'Assessment is read only'
        $script:FailHealth=$false

        $beforeRequests=$script:Requests
        $beforeFiles=@(Get-ChildItem -LiteralPath $OutputPath -File).Count
        $null=Invoke-CavCommand -Mode ExportResults -OutputDirectory $OutputPath -WhatIf
        Assert-Test ($script:Requests -eq $beforeRequests) 'Results WhatIf makes no requests and needs no token'
        Assert-Test (@(Get-ChildItem -LiteralPath $OutputPath -File).Count -eq $beforeFiles) 'Results WhatIf writes no files'
        Assert-Throws { Invoke-CavCommand -Mode ExportResults -ConfigPath $configPath -AccessToken $token -OutputDirectory $OutputPath -QueryId unknown -Confirm:$false } 'Unknown'
        Assert-Test ($script:Requests -eq $beforeRequests) 'Unknown result query rejected before network'
        $script:ExportFixture=$true
        $bundle=Invoke-CavCommand -Mode ExportResults -ConfigPath $configPath -AccessToken $token -OutputDirectory $OutputPath -Confirm:$false
        Assert-Test ($bundle.Status -eq 'CompletedWithQueryFailures') 'Failed result views do not stop the bundle'
        Assert-Test (@($bundle.Files).Count -eq 29) 'Nine CSV/JSON/KQL sets, HTML and manifest'
        Assert-Test ($script:Requests-$beforeRequests -eq 8) 'Unconfigured remediation view skipped before requests'
        Assert-Test ($script:Writes -eq 0) 'Results export never mutates tenant rules'
        foreach ($path in $bundle.Files) { Assert-Test ((Get-CavZoneId $path) -in 3,4) 'Result output metadata verified' }
        $manifest=ConvertFrom-CavJson (Get-Content -LiteralPath $bundle.ManifestPath -Raw)
        Assert-Test ($manifest.TenantId -eq $tenant -and $manifest.Context.LookbackDays -eq 7) 'Manifest records tenant and query window'
        Assert-Test (@($manifest.Views | Where-Object { $_.Status -eq 'ResultsReturned' }).Count -eq 1) 'Data view distinguished'
        Assert-Test (@($manifest.Views | Where-Object { $_.Status -eq 'QueryFailed' }).Count -eq 1) 'Failed view distinguished'
        Assert-Test (@($manifest.Views | Where-Object { $_.Status -eq 'NotConfigured' }).Count -eq 1) 'Missing configuration distinguished'
        Assert-Test (@($manifest.Views | Where-Object { $_.Status -eq 'NoResults' }).Count -eq 6) 'Empty results distinguished'
        $html=Get-Content -LiteralPath $bundle.DashboardPath -Raw
        Assert-Test ($html -notmatch '<script>' -and $html.Contains('&lt;script&gt;')) 'HTML encodes hostile result values'
        Assert-Test ($html.Contains('Content-Security-Policy') -and $html.Contains('HTML preview limited to 200 rows')) 'HTML uses offline policy and explicit preview cap'
        $csv=Get-Content -LiteralPath (Join-Path $OutputPath ($bundle.RunId+'-operations.csv')) -Raw
        Assert-Test ($csv.Contains("' =1+1")) 'CSV neutralizes formula-like cells after whitespace'
        $raw=ConvertFrom-CavJson (Get-Content -LiteralPath (Join-Path $OutputPath ($bundle.RunId+'-operations.json')) -Raw)
        Assert-Test ($raw.Results[0].Value -ceq ' =1+1' -and $raw.Results[0].Nested.labels.Count -eq 2) 'JSON preserves raw strings and nested values'
        Assert-Test ($raw.LimitIndicators.Count -eq 1 -and $raw.Completeness -eq 'NotGuaranteed') 'API warning flagged without completeness claim'
        $single=Invoke-CavCommand -Mode ExportResults -QueryId operations -ConfigPath $configPath -AccessToken $token -OutputDirectory $OutputPath -Confirm:$false
        Assert-Test ($single.Files.Count -eq 5 -and $single.RunId -ne $bundle.RunId) 'Single view export and collision-free repeated runs'
        $script:ExportFixture=$false; $script:MalformedExport=$true
        $malformed=Invoke-CavCommand -Mode ExportResults -QueryId operations -ConfigPath $configPath -AccessToken $token -OutputDirectory $OutputPath -Confirm:$false
        Assert-Test ($malformed.Views[0].Status -eq 'QueryFailed') 'Malformed API response is failure, not empty data'
        $script:MalformedExport=$false
        foreach ($cell in @('=1+1','+SUM(1)','-1','@SUM(1)',"`t=1+1","`r=1+1")) {
            Assert-Test ((ConvertTo-CavCsvField $cell).StartsWith('"'+"'")) 'CSV formula prefix protected'
        }
        $emptyCsv=ConvertTo-CavCsv -Schema @([pscustomobject]@{name='Column'}) -Rows @()
        Assert-Test ($emptyCsv -ceq "`"Column`"`r`n") 'Empty successful query keeps CSV schema header'

        $params=@{ Mode='Deploy'; ConfigPath=$configPath; AccessToken=$token; RuleId='cav-teams-endpoint-v1'; OutputDirectory=$OutputPath; Confirm=$false }
        Assert-Throws { Invoke-CavCommand @params } 'OverlapReviewed'
        $params.OverlapReviewed=$true
        $created=Invoke-CavCommand @params
        Assert-Test ($created.Status -eq 'Verified') 'Create verified'
        Assert-Test ($script:Store[$params.RuleId].status -ceq 'disabled') 'Created rule remains disabled'
        Assert-Test ($script:Writes -eq 1) 'One write for first deployment'
        $createReceipt=ConvertFrom-CavJson (Get-Content -LiteralPath $created.ReceiptPath -Raw)
        Assert-Test ($null -eq $createReceipt.PreviousDefinition) 'Create receipt has no prior rule'
        Assert-Throws { Invoke-CavCommand @params } 'already exists'
        Assert-Test ($script:Writes -eq 1) 'Repeat deployment does not duplicate'
        $script:Store[$params.RuleId].status='enabled'
        $params.UpdateExisting=$true
        Assert-Throws { Invoke-CavCommand @params } 'Only disabled'
        $script:Store[$params.RuleId].status='disabled'
        $updated=Invoke-CavCommand @params
        $updateReceipt=ConvertFrom-CavJson (Get-Content -LiteralPath $updated.ReceiptPath -Raw)
        Assert-Test ($updateReceipt.Operation -eq 'Update') 'Explicit update receipt'
        Assert-Test ($updateReceipt.PreviousDefinition.schedule.PSObject.Properties.Name -notcontains 'nextRunDateTime') 'Read-only schedule fields excluded'
        $rolled=Invoke-CavCommand -Mode Rollback -ConfigPath $configPath -AccessToken $token -ReceiptPath $updated.ReceiptPath -OutputDirectory $OutputPath -Confirm:$false
        Assert-Test ($rolled.Status -eq 'Verified') 'Updated definition restored'
        $script:Store[$params.RuleId].displayName='Concurrent edit'
        Assert-Throws { Invoke-CavCommand -Mode Rollback -ConfigPath $configPath -AccessToken $token -ReceiptPath $created.ReceiptPath -OutputDirectory $OutputPath -Confirm:$false } 'changed since'
        $script:Store[$params.RuleId].displayName='Cloud App Visibility: endpoint tool after reviewed Teams alert'
        $null=Invoke-CavCommand -Mode Rollback -ConfigPath $configPath -AccessToken $token -ReceiptPath $created.ReceiptPath -OutputDirectory $OutputPath -Confirm:$false
        Assert-Test ($script:Store.Count -eq 0) 'Create rollback deletes only its unchanged managed rule'

        $other=Clone-Test (Get-CavDefinition $context (Get-CavRule $context $params.RuleId))
        $other.id='external-rule'; $script:Store['external-rule']=$other
        Assert-Throws { Invoke-CavCommand @params } 'Possible duplicate'
        $script:Store.Clear()
        $script:FailReadback=$true
        Assert-Throws { Invoke-CavCommand @params } 'tenant may have changed'
        Assert-Test ($script:Store.Count -eq 1) 'Ambiguous write is not automatically undone or retried'
        Assert-Test (@(Get-ChildItem -LiteralPath $OutputPath -Filter '*-before.json').Count -gt 0) 'Recovery records persist after failure'
        Write-Host ("PASS: {0} mocked behavioral assertions; no live requests." -f $script:Checks)
    } $output
} finally {
    Remove-Module CloudAppVisibility -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $output -PathType Container) {
        Get-ChildItem -LiteralPath $output -File | Remove-Item -Force
        Remove-Item -LiteralPath $output -ErrorAction Stop
    }
}
