#Requires -Version 5.1

<#
.SYNOPSIS
    Audits Conditional Access policies and legacy authentication sign-ins affected
    by the Microsoft CA enforcement change (enforcement begins May 13, 2026).

.DESCRIPTION
    From May 13, 2026, CA policies targeting "All resources" with app exclusions will
    enforce consistently for sign-ins that previously bypassed enforcement due to
    limited OAuth scopes (OIDC, User.Read).

    This script produces an HTML report with:
      - All CA policies targeting all apps with exclusions, sorted by state
      - Legacy / ROPC authentication sign-ins that will break after enforcement

.PARAMETER TenantId
    Optional. Specify the tenant ID to connect to a specific tenant.

.PARAMETER OutputPath
    Optional. Path for the HTML report. Defaults to the temp folder.

.PARAMETER EnforcementDate
    Optional. The enforcement date used for labelling. Default: 2026-05-13.

.PARAMETER NoOpen
    Switch. Do not automatically open the report in the browser.

.EXAMPLE
    .\Get-CAEnforcementReport.ps1

.EXAMPLE
    .\Get-CAEnforcementReport.ps1 -TenantId "contoso.onmicrosoft.com"

.EXAMPLE
    .\Get-CAEnforcementReport.ps1 -EnforcementDate "2026-06-01"

.NOTES
    Required Graph permissions (delegated):
        Policy.Read.All
        Application.Read.All
        AuditLog.Read.All   (optional - needed for legacy auth sign-in detection)

    Required modules:
        Microsoft.Graph.Authentication
        Microsoft.Graph.Identity.SignIns
        Microsoft.Graph.Applications

    Author: Tenant Wizards (tenantwizards.nl)

.LINK
    https://tenantwizards.nl/blog/conditional-access-changes-may-13
#>

[CmdletBinding()]
param (
    [Parameter()] [string]$TenantId,
    [Parameter()] [string]$OutputPath = $env:TEMP,
    [Parameter()] [datetime]$EnforcementDate = [datetime]'2026-05-13',
    [Parameter()] [switch]$NoOpen
)

$ErrorActionPreference = 'Stop'

#region Helpers

function Get-StateLabel {
    param([string]$State)
    switch ($State) {
        'enabled'                           { 'Enabled' }
        'enabledForReportingButNotEnforced' { 'Report only' }
        'disabled'                          { 'Disabled' }
        default                             { $State }
    }
}

function Get-StateSortOrder {
    param([string]$State)
    switch ($State) {
        'enabled'                           { 0 }
        'enabledForReportingButNotEnforced' { 1 }
        'disabled'                          { 2 }
        default                             { 3 }
    }
}

function Get-HtmlStateClass {
    param([string]$State)
    switch ($State) {
        'enabled'                           { 'badge-red' }
        'enabledForReportingButNotEnforced' { 'badge-yellow' }
        'disabled'                          { 'badge-gray' }
        default                             { 'badge-gray' }
    }
}

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if (-not $Text) { return '' }
    $Text -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
}

#endregion

#region Module check

$requiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Applications'
)

foreach ($module in $requiredModules) {
    if (-not (Get-InstalledModule -Name $module -ErrorAction SilentlyContinue)) {
        Write-Warning "Module '$module' not installed. Run: Install-Module $module -Scope CurrentUser"
        exit 1
    }
    Import-Module $module -ErrorAction Stop
}

#endregion

#region Connect

$scopes = @('Policy.Read.All', 'Application.Read.All', 'AuditLog.Read.All')
$connectParams = @{ Scopes = $scopes; NoWelcome = $true }
if ($TenantId) { $connectParams['TenantId'] = $TenantId }

Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Gray
Connect-MgGraph @connectParams | Out-Null

$ctx = Get-MgContext
$tenantDisplay = $ctx.TenantId
try {
    $org = Get-MgOrganization -ErrorAction SilentlyContinue
    if ($org) { $tenantDisplay = "$($org.DisplayName) ($($ctx.TenantId))" }
} catch {}

Write-Host "Connected: $($ctx.Account) - $tenantDisplay" -ForegroundColor Gray

#endregion

#region Collect CA policies

Write-Host 'Fetching Conditional Access policies...' -ForegroundColor Gray

$allPolicies = @(Get-MgIdentityConditionalAccessPolicy -All)

$relevantPolicies = @(
    $allPolicies | Where-Object {
        $_.Conditions.Applications.IncludeApplications -contains 'All' -and
        $_.Conditions.Applications.ExcludeApplications.Count -gt 0
    } | Sort-Object { Get-StateSortOrder $_.State }
)

Write-Host "  Total policies: $($allPolicies.Count) | Relevant: $($relevantPolicies.Count)" -ForegroundColor Gray

$enabledCount  = @($relevantPolicies | Where-Object { $_.State -eq 'enabled' }).Count
$reportCount   = @($relevantPolicies | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }).Count
$disabledCount = @($relevantPolicies | Where-Object { $_.State -eq 'disabled' }).Count

# Cache app display names
$appNameCache = @{}

function Get-AppName {
    param([string]$AppId)
    if ($appNameCache.ContainsKey($AppId)) { return $appNameCache[$AppId] }
    try {
        $sp = Get-MgServicePrincipal -Filter "AppId eq '$AppId'" -ErrorAction SilentlyContinue |
              Select-Object -First 1
        $name = if ($sp) { $sp.DisplayName } else { $AppId }
    } catch { $name = $AppId }
    $appNameCache[$AppId] = $name
    return $name
}

#endregion

#region Collect legacy auth sign-ins

Write-Host 'Fetching legacy authentication sign-ins...' -ForegroundColor Gray

$legacySignIns = @()
$legacyError   = $null

try {
    $filter = "clientAppUsed ne 'Browser' and clientAppUsed ne 'Mobile Apps and Desktop clients' and status/errorCode eq 0"
    $uri    = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$filter&`$top=50&`$select=appDisplayName,userPrincipalName,clientAppUsed,createdDateTime"
    $resp   = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
    $legacySignIns = @($resp.value | Sort-Object appDisplayName)
    Write-Host "  Legacy sign-ins found: $($legacySignIns.Count)" -ForegroundColor Gray
} catch {
    $errMsg = $_.ToString()
    if ($errMsg -match '403|Forbidden') {
        $legacyError = 'AuditLog.Read.All permission not granted. Go to Entra > Enterprise applications > Microsoft Graph Command Line Tools > Permissions > Grant admin consent, then re-run.'
    } elseif ($errMsg -match 'license|P1|P2|Premium') {
        $legacyError = 'Sign-in logs require an Entra ID P1 or P2 license.'
    } else {
        $legacyError = "Could not retrieve sign-in logs: $errMsg"
    }
    Write-Host "  Unavailable: $legacyError" -ForegroundColor Yellow
}

#endregion

#region Build HTML

$generatedAt = Get-Date -Format 'yyyy-MM-dd HH:mm'

# Policy rows
$policyRowsHtml = ''

if ($relevantPolicies.Count -eq 0) {
    $policyRowsHtml = '<tr><td colspan="3" class="empty">No Conditional Access policies with this configuration found.</td></tr>'
} else {
    $currentState = $null
    foreach ($policy in $relevantPolicies) {
        $stateLabel = Get-StateLabel $policy.State
        $badgeClass = Get-HtmlStateClass $policy.State

        if ($policy.State -ne $currentState) {
            $currentState = $policy.State
            $policyRowsHtml += "<tr class=`"group-header`"><td colspan=`"3`">$stateLabel</td></tr>"
        }

        $appListHtml = ''
        foreach ($appId in $policy.Conditions.Applications.ExcludeApplications) {
            $appName      = Get-AppName $appId
            $appListHtml += "<li>$(ConvertTo-HtmlSafe $appName)</li>"
        }

        $policyRowsHtml += "
        <tr>
          <td>
            <span class=`"policy-name`">$(ConvertTo-HtmlSafe $policy.DisplayName)</span>
            <span class=`"policy-id`">$($policy.Id)</span>
          </td>
          <td><span class=`"badge $badgeClass`">$stateLabel</span></td>
          <td><ul class=`"app-list`">$appListHtml</ul></td>
        </tr>"
    }
}

# Legacy sign-in rows
$legacyRowsHtml = ''

if ($legacyError) {
    $legacyRowsHtml = "<tr><td colspan=`"4`" class=`"notice`">$(ConvertTo-HtmlSafe $legacyError)</td></tr>"
} elseif ($legacySignIns.Count -eq 0) {
    $legacyRowsHtml = '<tr><td colspan="4" class="empty">No recent legacy authentication sign-ins detected.</td></tr>'
} else {
    foreach ($entry in $legacySignIns) {
        $date = if ($entry.createdDateTime) {
            ([datetime]$entry.createdDateTime).ToString('yyyy-MM-dd HH:mm')
        } else { '-' }
        $legacyRowsHtml += "
        <tr>
          <td>$(ConvertTo-HtmlSafe $entry.appDisplayName)</td>
          <td>$(ConvertTo-HtmlSafe $entry.userPrincipalName)</td>
          <td>$(ConvertTo-HtmlSafe $entry.clientAppUsed)</td>
          <td>$date</td>
        </tr>"
    }
}

# Summary card colors
$totalColor  = if ($relevantPolicies.Count -gt 0) { 'red' } else { 'green' }
$enableColor = if ($enabledCount -gt 0) { 'red' } else { 'green' }
$repColor    = if ($reportCount -gt 0) { 'yellow' } else { 'gray' }
$legacyColor = if ($legacyError) { 'yellow' } elseif ($legacySignIns.Count -gt 0) { 'red' } else { 'green' }
$legacyValue = if ($legacyError) { '?' } else { $legacySignIns.Count }

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CA Enforcement Report - $tenantDisplay</title>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{background:#0e0e0e;color:#f0ece4;font-family:system-ui,-apple-system,sans-serif;font-size:14px;line-height:1.6;padding:0 0 60px}
    a{color:#e03030;text-decoration:none}

    .site-header{border-bottom:1px solid #262626;padding:20px 40px;display:flex;align-items:center;gap:16px}
    .logo{font-size:18px;font-weight:700;letter-spacing:-0.5px}
    .logo .bracket{color:#e03030}
    .header-divider{color:#262626;font-size:18px}
    .header-title{color:#8c8880;font-size:13px}
    .header-meta{color:#524f4c;font-size:12px;margin-left:auto;text-align:right}
    .header-meta strong{color:#8c8880;display:block}

    .container{max-width:1100px;margin:0 auto;padding:0 40px}
    h1{font-size:22px;font-weight:700;margin:40px 0 4px;color:#f0ece4}
    .subtitle{color:#8c8880;font-size:13px;margin-bottom:32px}
    h2{font-size:11px;font-weight:600;color:#524f4c;letter-spacing:0.1em;text-transform:uppercase;margin:40px 0 12px}

    .summary{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:8px}
    .card{background:#161616;border:1px solid #262626;border-radius:4px;padding:16px 20px}
    .card-value{font-size:28px;font-weight:700;line-height:1.1;margin-bottom:4px}
    .card-label{font-size:10px;color:#524f4c;text-transform:uppercase;letter-spacing:0.06em}
    .red{color:#e03030} .yellow{color:#fbbf24} .green{color:#4ade80} .gray{color:#524f4c}

    .table-wrap{background:#161616;border:1px solid #262626;border-radius:4px;overflow:hidden;margin-bottom:4px}
    table{width:100%;border-collapse:collapse}
    th{background:#1e1e1e;color:#524f4c;font-size:10px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;padding:10px 16px;text-align:left;border-bottom:1px solid #262626}
    td{padding:12px 16px;border-bottom:1px solid #1d1d1d;vertical-align:top;color:#f0ece4}
    tr:last-child td{border-bottom:none}
    tr:hover td{background:#1a1a1a}
    tr.group-header td{background:#1e1e1e;color:#524f4c;font-size:10px;font-weight:700;letter-spacing:0.1em;text-transform:uppercase;padding:6px 16px;border-bottom:1px solid #262626}
    tr.group-header:hover td{background:#1e1e1e}

    .policy-name{display:block;font-weight:600}
    .policy-id{display:block;font-size:11px;color:#524f4c;font-family:'Courier New',monospace;margin-top:2px}
    .app-list{list-style:none;padding:0}
    .app-list li{color:#8c8880;font-size:12px;padding:1px 0}
    .app-list li::before{content:'- ';color:#524f4c}

    td.empty{color:#524f4c;font-style:italic;padding:20px 16px;text-align:center}
    td.notice{color:#fbbf24;padding:16px;text-align:center}

    .badge{display:inline-block;font-size:10px;font-weight:700;letter-spacing:0.06em;text-transform:uppercase;padding:2px 7px;border-radius:2px}
    .badge-red   {background:rgba(224,48,48,.12);color:#f07070;border:1px solid rgba(224,48,48,.25)}
    .badge-yellow{background:rgba(251,191,36,.10);color:#fbbf24;border:1px solid rgba(251,191,36,.25)}
    .badge-gray  {background:rgba(82,79,76,.20);color:#524f4c;border:1px solid rgba(82,79,76,.30)}

    .note{color:#524f4c;font-size:12px;margin-bottom:12px}

    footer{margin-top:60px;padding:20px 40px;border-top:1px solid #262626;color:#524f4c;font-size:11px}
    footer a{color:#524f4c}
    footer a:hover{color:#8c8880}
  </style>
</head>
<body>

<header class="site-header">
  <div class="logo"><span class="bracket">[</span>TW<span class="bracket">]</span></div>
  <span class="header-divider">|</span>
  <span class="header-title">Conditional Access Enforcement Report</span>
  <div class="header-meta">
    <strong>$tenantDisplay</strong>
    Generated $generatedAt
  </div>
</header>

<div class="container">

  <h1>CA Enforcement Check</h1>
  <p class="subtitle">Policies targeting all cloud apps with resource exclusions, and legacy authentication sign-ins. Microsoft enforces this change from <strong style="color:#f0ece4">$($EnforcementDate.ToString('MMMM d, yyyy'))</strong>.</p>

  <h2>Summary</h2>
  <div class="summary">
    <div class="card">
      <div class="card-value $totalColor">$($relevantPolicies.Count)</div>
      <div class="card-label">Relevant policies</div>
    </div>
    <div class="card">
      <div class="card-value $enableColor">$enabledCount</div>
      <div class="card-label">Enabled</div>
    </div>
    <div class="card">
      <div class="card-value $repColor">$reportCount</div>
      <div class="card-label">Report only</div>
    </div>
    <div class="card">
      <div class="card-value gray">$disabledCount</div>
      <div class="card-label">Disabled</div>
    </div>
    <div class="card">
      <div class="card-value $legacyColor">$legacyValue</div>
      <div class="card-label">Legacy sign-ins</div>
    </div>
  </div>

  <h2>Conditional Access Policies</h2>
  <div class="table-wrap">
    <table>
      <thead><tr>
        <th style="width:45%">Policy</th>
        <th style="width:15%">State</th>
        <th>Excluded apps</th>
      </tr></thead>
      <tbody>$policyRowsHtml</tbody>
    </table>
  </div>

  <h2>Legacy Authentication Sign-ins</h2>
  <p class="note">Apps using protocols that cannot handle MFA (ROPC, EAS, IMAP, SMTP Auth, etc.). These will fail outright after $($EnforcementDate.ToString('MMMM d, yyyy')) if covered by an enforced CA policy. Showing up to 50 recent successful sign-ins.</p>
  <div class="table-wrap">
    <table>
      <thead><tr>
        <th>Application</th>
        <th>User</th>
        <th>Protocol</th>
        <th>Last seen</th>
      </tr></thead>
      <tbody>$legacyRowsHtml</tbody>
    </table>
  </div>

</div>

<footer>
  <div class="container" style="padding:0">
    <a href="https://techcommunity.microsoft.com/blog/microsoft-entra-blog/upcoming-conditional-access-change-improved-enforcement-for-policies-with-resour/4488925" target="_blank">Microsoft Entra Blog - CA enforcement change</a>
    &nbsp;&middot;&nbsp;
    <a href="https://tenantwizards.nl/blog/conditional-access-changes-may-13" target="_blank">tenantwizards.nl</a>
  </div>
</footer>

</body>
</html>
"@

#endregion

#region Save and open

$timestamp  = Get-Date -Format 'yyyyMMdd-HHmm'
$reportFile = Join-Path $OutputPath "TW-CA-Report-$timestamp.html"

[System.IO.File]::WriteAllText($reportFile, $html, [System.Text.UTF8Encoding]::new($false))

Write-Host ""
Write-Host "Report saved: $reportFile" -ForegroundColor Cyan

if (-not $NoOpen) { Start-Process $reportFile }

#endregion

Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null