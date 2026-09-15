#Requires -Version 5.1

<#
.SYNOPSIS
    Audits Conditional Access policies for a block on device code flow and
    authentication transfer, the flow abused in the September 2026
    passkey-themed vishing campaign (Storm-3121 / Storm-3032).

.DESCRIPTION
    Microsoft's September 9, 2026 report on this campaign recommends
    blocking the device code and authentication transfer flows via
    Conditional Access, except where an explicit business need exists.
    Phishing-resistant MFA does not stop this attack path: the victim signs
    into a real Microsoft page with a real code, so no credential or
    passkey is ever phished.

    This script reads your Conditional Access policies directly via
    Microsoft Graph and reports, for each flow (device code flow,
    authentication transfer), whether an ENABLED policy blocks it, only a
    report-only policy exists, or nothing targets it at all.

    This script does NOT tell you whether device code flow is actually in
    use in your tenant for a legitimate reason (shared devices, digital
    signage, some legacy tooling). Check your sign-in logs filtered on the
    device-code authentication protocol before enforcing a block, and roll
    out any new policy in report-only mode first.

.PARAMETER TenantId
    Optional. Specify the tenant ID to connect to a specific tenant.

.PARAMETER OutputPath
    Optional. Path for the HTML report. Defaults to the temp folder.

.PARAMETER NoOpen
    Switch. Do not automatically open the report in the browser.

.PARAMETER DeviceCode
    Switch. Use device code sign-in instead of the default interactive
    browser (WAM) flow. Use this when running from a remote session, a
    headless/background process, or anywhere without a window handle for
    WAM to anchor to ("A window handle must be configured" error).

.EXAMPLE
    .\Get-AuthFlowsBlockReport.ps1

.EXAMPLE
    .\Get-AuthFlowsBlockReport.ps1 -TenantId "contoso.onmicrosoft.com"

.NOTES
    Required Graph permissions (delegated):
        Policy.Read.All

    Required modules:
        Microsoft.Graph.Authentication

    Author: Tenant Wizards (tenantwizards.nl)

.LINK
    https://tenantwizards.nl/blog/passkey-vishing-microsoft-365-2026
#>

[CmdletBinding()]
param (
    [Parameter()] [string]$TenantId,
    [Parameter()] [string]$OutputPath = $env:TEMP,
    [Parameter()] [switch]$NoOpen,
    [Parameter()] [switch]$DeviceCode
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

function Get-HtmlStateClass {
    param([string]$State)
    switch ($State) {
        'enabled'                           { 'badge-green' }
        'enabledForReportingButNotEnforced' { 'badge-yellow' }
        'disabled'                          { 'badge-gray' }
        default                             { 'badge-gray' }
    }
}

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if (-not $Text) { return '' }
    $Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;'
}

# A policy only actually blocks the flow if its grant control is "block" AND
# it targets the flow AND it's enabled (not just report-only or disabled).
function Test-BlocksFlow {
    param($Policy, [string]$FlowName)
    $transferMethods = $Policy.conditions.authenticationFlows.transferMethods
    if (-not $transferMethods) { return $false }
    $targetsFlow = $transferMethods -split ',' -contains $FlowName
    $isBlockGrant = $Policy.grantControls -and ($Policy.grantControls.builtInControls -contains 'block')
    return ($targetsFlow -and $isBlockGrant)
}

function Test-TargetsFlow {
    param($Policy, [string]$FlowName)
    $transferMethods = $Policy.conditions.authenticationFlows.transferMethods
    if (-not $transferMethods) { return $false }
    return ($transferMethods -split ',' -contains $FlowName)
}

#endregion

#region Module check

$requiredModules = @('Microsoft.Graph.Authentication')

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Warning "Module '$module' not installed. Run: Install-Module $module -Scope CurrentUser"
        exit 1
    }
    Import-Module $module -ErrorAction Stop
}

#endregion

#region Connect

$scopes = @('Policy.Read.All')
$connectParams = @{ Scopes = $scopes; NoWelcome = $true }
if ($TenantId) { $connectParams['TenantId'] = $TenantId }
if ($DeviceCode) { $connectParams['UseDeviceCode'] = $true }

Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Gray
if ($DeviceCode) { Write-Host '(Device code sign-in: a code and URL will appear below. Open the URL on any device and enter the code.)' -ForegroundColor Gray }
Connect-MgGraph @connectParams | Out-Null

$ctx = Get-MgContext
$tenantDisplay = $ctx.TenantId
try {
    $org = Get-MgOrganization -ErrorAction SilentlyContinue
    if ($org) { $tenantDisplay = "$($org.DisplayName) ($($ctx.TenantId))" }
} catch {}

Write-Host "Connected: $($ctx.Account) - $tenantDisplay" -ForegroundColor Gray

#endregion

#region Collect Conditional Access policies

Write-Host 'Fetching Conditional Access policies...' -ForegroundColor Gray

# Fetched via raw REST (not the typed Get-MgIdentityConditionalAccessPolicy
# cmdlet) so this doesn't depend on the installed SDK version's model having
# caught up with the authenticationFlows condition.
$allPolicies = @()
$uri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$top=999'
do {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
    $allPolicies += $resp.value
    $uri = $resp.'@odata.nextLink'
} while ($uri)

$flowPolicies = @($allPolicies | Where-Object {
    (Test-TargetsFlow $_ 'deviceCodeFlow') -or (Test-TargetsFlow $_ 'authenticationTransfer')
})

Write-Host "  Total policies: $($allPolicies.Count) | Targeting an authentication flow: $($flowPolicies.Count)" -ForegroundColor Gray

$deviceCodeBlocked = [bool](@($flowPolicies | Where-Object { $_.state -eq 'enabled' -and (Test-BlocksFlow $_ 'deviceCodeFlow') }).Count)
$deviceCodeReportOnly = [bool](@($flowPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' -and (Test-TargetsFlow $_ 'deviceCodeFlow') }).Count)
$authTransferBlocked = [bool](@($flowPolicies | Where-Object { $_.state -eq 'enabled' -and (Test-BlocksFlow $_ 'authenticationTransfer') }).Count)
$authTransferReportOnly = [bool](@($flowPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' -and (Test-TargetsFlow $_ 'authenticationTransfer') }).Count)

function Get-FlowStatusLabel {
    param([bool]$Blocked, [bool]$ReportOnly)
    if ($Blocked) { 'Blocked' } elseif ($ReportOnly) { 'Report-only' } else { 'Not blocked' }
}
function Get-FlowStatusColor {
    param([bool]$Blocked, [bool]$ReportOnly)
    if ($Blocked) { 'green' } elseif ($ReportOnly) { 'yellow' } else { 'red' }
}

$deviceCodeStatus = Get-FlowStatusLabel $deviceCodeBlocked $deviceCodeReportOnly
$authTransferStatus = Get-FlowStatusLabel $authTransferBlocked $authTransferReportOnly

Write-Host "  Device code flow: $deviceCodeStatus | Authentication transfer: $authTransferStatus" -ForegroundColor Gray

#endregion

#region Build HTML

$generatedAt = Get-Date -Format 'yyyy-MM-dd HH:mm'

$policyRowsHtml = ''
if ($flowPolicies.Count -eq 0) {
    $policyRowsHtml = '<tr><td colspan="5" class="empty">No Conditional Access policy targets device code flow or authentication transfer.</td></tr>'
} else {
    foreach ($policy in ($flowPolicies | Sort-Object { $_.state -ne 'enabled' }, displayName)) {
        $stateLabel = Get-StateLabel $policy.state
        $badgeClass = Get-HtmlStateClass $policy.state
        $flows = @()
        if (Test-TargetsFlow $policy 'deviceCodeFlow') { $flows += 'Device code flow' }
        if (Test-TargetsFlow $policy 'authenticationTransfer') { $flows += 'Authentication transfer' }
        $grantIsBlock = $policy.grantControls -and ($policy.grantControls.builtInControls -contains 'block')
        $grantLabel = if ($grantIsBlock) { 'Block access' } else { ($policy.grantControls.builtInControls -join ', ') }
        $policyRowsHtml += "
        <tr>
          <td>
            <span class=`"policy-name`">$(ConvertTo-HtmlSafe $policy.displayName)</span>
            <span class=`"policy-id`">$($policy.id)</span>
          </td>
          <td><span class=`"badge $badgeClass`">$stateLabel</span></td>
          <td>$(ConvertTo-HtmlSafe ($flows -join ', '))</td>
          <td>$(ConvertTo-HtmlSafe $grantLabel)</td>
        </tr>"
    }
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authentication Flows Block Report - $tenantDisplay</title>
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

    .summary{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-bottom:8px}
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

    .policy-name{display:block;font-weight:600}
    .policy-id{display:block;font-size:11px;color:#524f4c;font-family:'Courier New',monospace;margin-top:2px}

    td.empty{color:#524f4c;font-style:italic;padding:20px 16px;text-align:center}

    .badge{display:inline-block;font-size:10px;font-weight:700;letter-spacing:0.06em;text-transform:uppercase;padding:2px 7px;border-radius:2px}
    .badge-green {background:rgba(74,222,128,.10);color:#4ade80;border:1px solid rgba(74,222,128,.25)}
    .badge-yellow{background:rgba(251,191,36,.10);color:#fbbf24;border:1px solid rgba(251,191,36,.25)}
    .badge-gray  {background:rgba(82,79,76,.20);color:#524f4c;border:1px solid rgba(82,79,76,.30)}

    footer{margin-top:60px;padding:20px 40px;border-top:1px solid #262626;color:#524f4c;font-size:11px}
    footer a{color:#524f4c}
    footer a:hover{color:#8c8880}
  </style>
</head>
<body>

<header class="site-header">
  <div class="logo"><span class="bracket">[</span>TW<span class="bracket">]</span></div>
  <span class="header-divider">|</span>
  <span class="header-title">Authentication Flows Block Report</span>
  <div class="header-meta">
    <strong>$tenantDisplay</strong>
    Generated $generatedAt
  </div>
</header>

<div class="container">

  <h1>Device code flow / authentication transfer check</h1>
  <p class="subtitle">Whether an enabled Conditional Access policy blocks the flows abused in the September 2026 passkey-themed vishing campaign (Storm-3121, Storm-3032).</p>
  <p class="caveat">This only reports what your policies are configured to do. It does not tell you whether device code flow is actually in use in your tenant for a legitimate reason (shared devices, digital signage, some legacy tooling). Check sign-in logs filtered on the device-code authentication protocol, and roll out any new block in report-only mode first.</p>

  <h2>Summary</h2>
  <div class="summary">
    <div class="card">
      <div class="card-value $(Get-FlowStatusColor $deviceCodeBlocked $deviceCodeReportOnly)">$deviceCodeStatus</div>
      <div class="card-label">Device code flow</div>
    </div>
    <div class="card">
      <div class="card-value $(Get-FlowStatusColor $authTransferBlocked $authTransferReportOnly)">$authTransferStatus</div>
      <div class="card-label">Authentication transfer</div>
    </div>
  </div>

  <h2>Policies targeting an authentication flow</h2>
  <div class="table-wrap">
    <table>
      <thead><tr>
        <th style="width:36%">Policy</th>
        <th style="width:14%">State</th>
        <th style="width:26%">Flow(s) targeted</th>
        <th>Grant control</th>
      </tr></thead>
      <tbody>$policyRowsHtml</tbody>
    </table>
  </div>

</div>

<footer>
  <div class="container" style="padding:0">
    <a href="https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows" target="_blank">Microsoft Learn - Block authentication flows with Conditional Access</a>
    &nbsp;&middot;&nbsp;
    <a href="https://tenantwizards.nl/blog/passkey-vishing-microsoft-365-2026" target="_blank">tenantwizards.nl</a>
  </div>
</footer>

</body>
</html>
"@

#endregion

#region Save and open

$timestamp  = Get-Date -Format 'yyyyMMdd-HHmm'
$reportFile = Join-Path $OutputPath "TW-AuthFlows-Report-$timestamp.html"

[System.IO.File]::WriteAllText($reportFile, $html, [System.Text.UTF8Encoding]::new($false))

Write-Host ""
Write-Host "Report saved: $reportFile" -ForegroundColor Cyan

if (-not $NoOpen) { Start-Process $reportFile }

#endregion

Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
