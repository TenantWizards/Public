#Requires -Version 5.1

<#
.SYNOPSIS
    Inventories apps in your tenant granted User.ReadBasic.All, ahead of the
    Microsoft Graph permission change announced in MC1470871.

.DESCRIPTION
    MC1470871: User.ReadBasic.All currently allows reading a user's app role
    assignments and license details, on top of its intended basic profile
    scope. Microsoft is closing that gap in a rollout completing late
    September 2026. Apps that rely on the unintended access need
    User.Read.All (app role assignments) or LicenseAssignment.Read.All
    (license details) instead.

    This script does NOT tell you whether an app's code actually calls the
    affected endpoints — Microsoft Graph does not log that level of detail
    by default. It tells you which apps hold User.ReadBasic.All, and
    whether they already also hold a permission that would keep the
    equivalent calls working. Apps flagged "Needs review" are not
    guaranteed to break; they're the ones worth checking by hand before the
    rollout reaches your tenant.

    Produces an HTML report with:
      - Every app (delegated or application grant) holding User.ReadBasic.All
      - Whether that same grant also already includes User.Read.All or
        LicenseAssignment.Read.All
      - A risk flag: Needs review vs. Likely covered

.PARAMETER TenantId
    Optional. Specify the tenant ID to connect to a specific tenant.

.PARAMETER OutputPath
    Optional. Path for the HTML report. Defaults to the temp folder.

.PARAMETER NoOpen
    Switch. Do not automatically open the report in the browser.

.EXAMPLE
    .\Get-ReadBasicAllExposureReport.ps1

.EXAMPLE
    .\Get-ReadBasicAllExposureReport.ps1 -TenantId "contoso.onmicrosoft.com"

.NOTES
    Required Graph permissions (delegated):
        Application.Read.All   (resolve app names, read application-permission grants)
        Directory.Read.All     (read delegated-permission grants)

    Required modules:
        Microsoft.Graph.Authentication
        Microsoft.Graph.Applications

    Author: Tenant Wizards (tenantwizards.nl)

.LINK
    https://tenantwizards.nl/blog/user-readbasic-all-graph-permission-change-2026
#>

[CmdletBinding()]
param (
    [Parameter()] [string]$TenantId,
    [Parameter()] [string]$OutputPath = $env:TEMP,
    [Parameter()] [switch]$NoOpen
)

$ErrorActionPreference = 'Stop'

$GraphResourceAppId = '00000003-0000-0000-c000-000000000000'
$WatchedPermissions = @('User.ReadBasic.All', 'User.Read.All', 'LicenseAssignment.Read.All')

#region Helpers

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if (-not $Text) { return '' }
    $Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;'
}

function Get-YesNoBadge {
    param([bool]$Value)
    if ($Value) { '<span class="badge badge-green">Yes</span>' }
    else { '<span class="badge badge-gray">No</span>' }
}

#endregion

#region Module check

$requiredModules = @(
    'Microsoft.Graph.Authentication',
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

$scopes = @('Application.Read.All', 'Directory.Read.All')
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

#region Resolve Microsoft Graph's own service principal and permission IDs

Write-Host 'Resolving Microsoft Graph permission IDs...' -ForegroundColor Gray

$graphSp = Get-MgServicePrincipal -Filter "appId eq '$GraphResourceAppId'" -ErrorAction Stop |
    Select-Object -First 1

if (-not $graphSp) {
    Write-Warning 'Could not find the Microsoft Graph service principal in this tenant.'
    exit 1
}

# appRoleId -> permission name (application permissions)
$appRoleNameById = @{}
foreach ($role in $graphSp.AppRoles) {
    if ($WatchedPermissions -contains $role.Value) {
        $appRoleNameById[$role.Id] = $role.Value
    }
}

$missingAppRoles = $WatchedPermissions | Where-Object { $appRoleNameById.Values -notcontains $_ }
if ($missingAppRoles) {
    Write-Warning "Could not find these permissions as application roles on the Graph service principal (may not exist as application permissions, or naming has changed): $($missingAppRoles -join ', ')"
}

#endregion

#region Collect application-permission grants (appRoleAssignedTo)

Write-Host 'Fetching application permission grants...' -ForegroundColor Gray

# clientObjectId -> [permission names granted, application type]
$appGrantsByClient = @{}

try {
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$($graphSp.Id)/appRoleAssignedTo?`$top=999"
    do {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        foreach ($assignment in $resp.value) {
            if (-not $appRoleNameById.ContainsKey($assignment.appRoleId)) { continue }
            $permName = $appRoleNameById[$assignment.appRoleId]
            $clientId = $assignment.principalId
            if (-not $appGrantsByClient.ContainsKey($clientId)) {
                $appGrantsByClient[$clientId] = [ordered]@{
                    DisplayName = $assignment.principalDisplayName
                    Permissions = [System.Collections.Generic.HashSet[string]]::new()
                }
            }
            [void]$appGrantsByClient[$clientId].Permissions.Add($permName)
        }
        $uri = $resp.'@odata.nextLink'
    } while ($uri)
    Write-Host "  Clients with a watched application permission: $($appGrantsByClient.Count)" -ForegroundColor Gray
} catch {
    Write-Warning "Could not read application permission grants: $($_.ToString())"
}

#endregion

#region Collect delegated-permission grants (oauth2PermissionGrants)

Write-Host 'Fetching delegated permission grants...' -ForegroundColor Gray

# clientObjectId -> [permission names granted]
$delegatedGrantsByClient = @{}

try {
    $filter = "resourceId eq '$($graphSp.Id)'"
    $uri = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=$filter&`$top=999"
    do {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        foreach ($grant in $resp.value) {
            if (-not $grant.scope) { continue }
            $grantedScopes = $grant.scope -split '\s+' | Where-Object { $_ -in $WatchedPermissions }
            if (-not $grantedScopes) { continue }
            $clientId = $grant.clientId
            if (-not $delegatedGrantsByClient.ContainsKey($clientId)) {
                $delegatedGrantsByClient[$clientId] = [System.Collections.Generic.HashSet[string]]::new()
            }
            foreach ($s in $grantedScopes) { [void]$delegatedGrantsByClient[$clientId].Add($s) }
        }
        $uri = $resp.'@odata.nextLink'
    } while ($uri)
    Write-Host "  Clients with a watched delegated permission: $($delegatedGrantsByClient.Count)" -ForegroundColor Gray
} catch {
    Write-Warning "Could not read delegated permission grants: $($_.ToString())"
}

#endregion

#region Resolve app display names for delegated clients (application-side names came free above)

$appNameCache = @{}
foreach ($id in $appGrantsByClient.Keys) { $appNameCache[$id] = $appGrantsByClient[$id].DisplayName }

function Get-AppName {
    param([string]$ClientObjectId)
    if ($appNameCache.ContainsKey($ClientObjectId)) { return $appNameCache[$ClientObjectId] }
    try {
        $sp = Get-MgServicePrincipal -ServicePrincipalId $ClientObjectId -ErrorAction SilentlyContinue
        $name = if ($sp) { $sp.DisplayName } else { $ClientObjectId }
    } catch { $name = $ClientObjectId }
    $appNameCache[$ClientObjectId] = $name
    return $name
}

#endregion

#region Build the flat report rows (one row per client + grant type that has User.ReadBasic.All)

$rows = @()

foreach ($clientId in $appGrantsByClient.Keys) {
    $perms = $appGrantsByClient[$clientId].Permissions
    if (-not $perms.Contains('User.ReadBasic.All')) { continue }
    $rows += [pscustomobject]@{
        AppName      = $appGrantsByClient[$clientId].DisplayName
        ClientId     = $clientId
        GrantType    = 'Application'
        HasUserReadAll = $perms.Contains('User.Read.All')
        HasLicenseReadAll = $perms.Contains('LicenseAssignment.Read.All')
    }
}

foreach ($clientId in $delegatedGrantsByClient.Keys) {
    $perms = $delegatedGrantsByClient[$clientId]
    if (-not $perms.Contains('User.ReadBasic.All')) { continue }
    $rows += [pscustomobject]@{
        AppName      = Get-AppName $clientId
        ClientId     = $clientId
        GrantType    = 'Delegated'
        HasUserReadAll = $perms.Contains('User.Read.All')
        HasLicenseReadAll = $perms.Contains('LicenseAssignment.Read.All')
    }
}

$rows = $rows | Sort-Object @{Expression = { $_.HasUserReadAll -or $_.HasLicenseReadAll } }, AppName

$needsReviewCount = @($rows | Where-Object { -not ($_.HasUserReadAll -or $_.HasLicenseReadAll) }).Count
$coveredCount     = @($rows | Where-Object { $_.HasUserReadAll -or $_.HasLicenseReadAll }).Count

Write-Host "  Total grants of User.ReadBasic.All found: $($rows.Count) | Needs review: $needsReviewCount | Likely covered: $coveredCount" -ForegroundColor Gray

#endregion

#region Build HTML

$generatedAt = Get-Date -Format 'yyyy-MM-dd HH:mm'

$rowsHtml = ''
if ($rows.Count -eq 0) {
    $rowsHtml = '<tr><td colspan="5" class="empty">No apps found with User.ReadBasic.All granted.</td></tr>'
} else {
    foreach ($row in $rows) {
        $covered = $row.HasUserReadAll -or $row.HasLicenseReadAll
        $riskBadge = if ($covered) { '<span class="badge badge-green">Likely covered</span>' } else { '<span class="badge badge-red">Needs review</span>' }
        $rowsHtml += "
        <tr>
          <td>
            <span class=`"app-name`">$(ConvertTo-HtmlSafe $row.AppName)</span>
            <span class=`"app-id`">$($row.ClientId)</span>
          </td>
          <td>$($row.GrantType)</td>
          <td>$(Get-YesNoBadge $row.HasUserReadAll)</td>
          <td>$(Get-YesNoBadge $row.HasLicenseReadAll)</td>
          <td>$riskBadge</td>
        </tr>"
    }
}

$totalColor  = if ($rows.Count -gt 0) { 'red' } else { 'green' }
$reviewColor = if ($needsReviewCount -gt 0) { 'red' } else { 'green' }

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>User.ReadBasic.All Exposure Report - $tenantDisplay</title>
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
    .subtitle{color:#8c8880;font-size:13px;margin-bottom:12px}
    .caveat{color:#fbbf24;font-size:12px;background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.2);border-radius:4px;padding:10px 14px;margin-bottom:32px}
    h2{font-size:11px;font-weight:600;color:#524f4c;letter-spacing:0.1em;text-transform:uppercase;margin:40px 0 12px}

    .summary{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:8px}
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

    .app-name{display:block;font-weight:600}
    .app-id{display:block;font-size:11px;color:#524f4c;font-family:'Courier New',monospace;margin-top:2px}

    td.empty{color:#524f4c;font-style:italic;padding:20px 16px;text-align:center}

    .badge{display:inline-block;font-size:10px;font-weight:700;letter-spacing:0.06em;text-transform:uppercase;padding:2px 7px;border-radius:2px}
    .badge-red  {background:rgba(224,48,48,.12);color:#f07070;border:1px solid rgba(224,48,48,.25)}
    .badge-green{background:rgba(74,222,128,.10);color:#4ade80;border:1px solid rgba(74,222,128,.25)}
    .badge-gray {background:rgba(82,79,76,.20);color:#524f4c;border:1px solid rgba(82,79,76,.30)}

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
  <span class="header-title">User.ReadBasic.All Exposure Report</span>
  <div class="header-meta">
    <strong>$tenantDisplay</strong>
    Generated $generatedAt
  </div>
</header>

<div class="container">

  <h1>MC1470871 Exposure Check</h1>
  <p class="subtitle">Apps holding User.ReadBasic.All, and whether they already also hold a permission that keeps app-role-assignment or license reads working after the rollout completes (late September 2026).</p>
  <p class="caveat">This is an inventory of permission grants, not proof of actual API usage. Microsoft Graph does not log which specific endpoint a call touched under a broad grant, so a "Needs review" app is not guaranteed to break, and a "Likely covered" app is not guaranteed to be unaffected. Confirm by testing the actual call before you rely on this report alone.</p>

  <h2>Summary</h2>
  <div class="summary">
    <div class="card">
      <div class="card-value $totalColor">$($rows.Count)</div>
      <div class="card-label">Grants of User.ReadBasic.All</div>
    </div>
    <div class="card">
      <div class="card-value $reviewColor">$needsReviewCount</div>
      <div class="card-label">Needs review</div>
    </div>
    <div class="card">
      <div class="card-value green">$coveredCount</div>
      <div class="card-label">Likely covered</div>
    </div>
  </div>

  <h2>Apps</h2>
  <div class="table-wrap">
    <table>
      <thead><tr>
        <th style="width:36%">App</th>
        <th style="width:14%">Grant type</th>
        <th style="width:16%">Has User.Read.All</th>
        <th style="width:16%">Has LicenseAssignment.Read.All</th>
        <th>Risk</th>
      </tr></thead>
      <tbody>$rowsHtml</tbody>
    </table>
  </div>

</div>

<footer>
  <div class="container" style="padding:0">
    <a href="https://learn.microsoft.com/en-us/graph/api/user-list-approleassignments?view=graph-rest-1.0" target="_blank">Microsoft Learn - appRoleAssignments endpoint</a>
    &nbsp;&middot;&nbsp;
    <a href="https://tenantwizards.nl/blog/user-readbasic-all-graph-permission-change-2026" target="_blank">tenantwizards.nl</a>
  </div>
</footer>

</body>
</html>
"@

#endregion

#region Save and open

$timestamp  = Get-Date -Format 'yyyyMMdd-HHmm'
$reportFile = Join-Path $OutputPath "TW-ReadBasicAll-Report-$timestamp.html"

[System.IO.File]::WriteAllText($reportFile, $html, [System.Text.UTF8Encoding]::new($false))

Write-Host ""
Write-Host "Report saved: $reportFile" -ForegroundColor Cyan

if (-not $NoOpen) { Start-Process $reportFile }

#endregion

Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
