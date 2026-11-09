#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
    [ValidateSet('Plan','Export','ExportResults','Assess','Hunt','Deploy','Rollback')][string]$Mode='Plan',
    [string]$ConfigPath=(Join-Path $PSScriptRoot 'config.example.json'),
    [Security.SecureString]$AccessToken,
    [string]$QueryId,
    [string]$RuleId,
    [string]$OutputDirectory,
    [string]$ReceiptPath,
    [switch]$IncludeRuleInventory,
    [switch]$OverlapReviewed,
    [switch]$UpdateExisting
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'CloudAppVisibility.psm1') -Force -ErrorAction Stop
Invoke-CavCommand @PSBoundParameters
