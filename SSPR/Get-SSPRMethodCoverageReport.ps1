#Requires -Version 5.1

<#
.SYNOPSIS
    Reports which SSPR-enabled users are not actually covered by your
    "number of methods required" policy, ahead of the Microsoft Graph
    change announced in MC1325414.

.DESCRIPTION
    MC1325414: starting November 7, 2026 (per the notice body; see the
    linked blog post for why that date is itself unsettled across
    Microsoft's own sources), SSPR stops accepting directory-sourced
    contact info that was never explicitly registered. Separately, and
    not new with this change, Microsoft Authenticator, software OATH
    tokens, and hardware OATH tokens all count as ONE authentication
    method for SSPR, FIDO2 and Windows Hello for Business can't be used
    for SSPR at all, and SMS/voice delivery is being retired in 2027.
    A user who looks "registered" in a headcount report can still be
    unable to complete an actual password reset because of any of these.

    This script does NOT re-implement Microsoft's method-counting rules
    itself. It calls the same Microsoft Graph report Entra ID uses
    internally (GET /reports/authenticationMethods/userRegistrationDetails)
    and reads the isSsprCapable flag Microsoft already computes per user,
    which is the authoritative answer to "can this user actually use SSPR
    today." What this script adds on top is a plain-language "Likely
    cause" for every user who is NOT capable, worked out from their
    methodsRegistered list using the category rules from the blog post
    below, plus a separate "durability watch" flag for users who are
    capable today only via a method Microsoft is retiring in 2027.

    The "Likely cause" column is explanatory, not authoritative. The
    mapping from raw methodsRegistered values (for example
    "microsoftAuthenticatorPush", "softwareOneTimePasscode", "mobilePhone")
    to the categories described in the blog post is this script's own
    best-effort reading of Microsoft's documented values, not something
    Microsoft's API returns directly. An unrecognized or future method
    value is shown as "Other: <raw value>" rather than guessed at.

    This also can't detect the November 7 directory-sourced-fallback
    change specifically: Microsoft doesn't expose, per user, whether a
    registered phone number or email came from the user actually
    registering it versus being synced in from the directory and never
    confirmed. isSsprCapable reflects Microsoft's live policy evaluation
    at the time you run this, so if you run it after enforcement starts,
    directory-only values are already excluded from it; if you run it
    before, they may still be counted. Re-run after the enforcement date
    changes anything for your tenant.

    Produces an HTML report with:
      - Every SSPR-enabled user who is not SSPR-capable today, with a
        plain-language likely cause
      - Every SSPR-capable user whose coverage depends on SMS or voice
        call, flagged as a durability risk ahead of the 2027 retirement
      - Admin accounts (Microsoft Entra administrator roles face a
        stricter policy; isAdmin is shown for every flagged row)

.PARAMETER TenantId
    Optional. Specify the tenant ID to connect to a specific tenant.

.PARAMETER IncludeAllUsers
    Switch. By default, only users enabled for SSPR are retrieved
    (isSsprEnabled eq true), since users outside SSPR scope aren't
    relevant to this report. Pass this switch to retrieve every user's
    registration details regardless of SSPR enablement.

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
    .\Get-SSPRMethodCoverageReport.ps1

.EXAMPLE
    .\Get-SSPRMethodCoverageReport.ps1 -TenantId "contoso.onmicrosoft.com"

.EXAMPLE
    .\Get-SSPRMethodCoverageReport.ps1 -IncludeAllUsers -DeviceCode

.NOTES
    Required Graph permission (delegated):
        AuditLog.Read.All

    The signed-in account also needs one of these Microsoft Entra roles
    (the Graph scope alone is not enough for this specific report):
        Reports Reader, Security Reader, Security Administrator, Global Reader

    Required module:
        Microsoft.Graph.Authentication

    Author: Tenant Wizards (tenantwizards.com)

.LINK
    https://tenantwizards.com/blog/sspr-registered-methods-november-2026
#>

[CmdletBinding()]
param (
    [Parameter()] [string]$TenantId,
    [Parameter()] [switch]$IncludeAllUsers,
    [Parameter()] [string]$OutputPath = $env:TEMP,
    [Parameter()] [switch]$NoOpen,
    [Parameter()] [switch]$DeviceCode
)

$ErrorActionPreference = 'Stop'

#region Helpers

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if (-not $Text) { return '' }
    $Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;'
}

# Best-effort mapping from raw methodsRegistered values to the SSPR
# categories described in the blog post. Not an authoritative Microsoft
# source for this mapping — see the .DESCRIPTION caveat above.
$CategoryMap = @{
    'microsoftAuthenticatorPush'         = 'AuthenticatorOrOATH'
    'microsoftAuthenticatorPasswordless' = 'AuthenticatorOrOATH'
    'softwareOneTimePasscode'            = 'AuthenticatorOrOATH'
    'hardwareOneTimePasscode'            = 'AuthenticatorOrOATH'
    'appNotification'                    = 'AuthenticatorOrOATH'   # legacy name for push
    'appCode'                            = 'AuthenticatorOrOATH'   # legacy name for OATH code
    'mobilePhone'                        = 'MobilePhone'
    'sms'                                = 'MobilePhone'
    'mobileSMS'                          = 'MobilePhone'           # legacy name
    'mobileCall'                         = 'MobilePhone'           # legacy name
    'officePhone'                        = 'OfficePhone'
    'email'                              = 'Email'
    'securityQuestion'                   = 'SecurityQuestion'
    'fido2SecurityKey'                   = 'FIDO2'
    'fido'                               = 'FIDO2'
    'windowsHelloForBusiness'            = 'WindowsHello'
    'passKeyDeviceBound'                 = 'Passkey'
    'passKeyDeviceBoundAuthenticator'    = 'Passkey'
    'passKeyDeviceBoundWindowsHello'     = 'Passkey'
    'passKeySynced'                      = 'Passkey'
}

# Categories that actually count toward Microsoft's "number of methods
# required" SSPR check. Alternate mobile phone, security questions'
# per-account-type quirks, and anything in $CategoryMap not listed here
# (FIDO2, WindowsHello, Passkey) are deliberately excluded: the blog post
# this script accompanies only verified SSPR eligibility for the
# categories below.
$SsprEligibleCategories = @('AuthenticatorOrOATH', 'MobilePhone', 'OfficePhone', 'Email', 'SecurityQuestion')

function Get-MethodCategories {
    param([string[]]$Methods)
    $categories = [System.Collections.Generic.HashSet[string]]::new()
    $unrecognized = [System.Collections.Generic.List[string]]::new()
    foreach ($m in $Methods) {
        if ($CategoryMap.ContainsKey($m)) {
            [void]$categories.Add($CategoryMap[$m])
        } else {
            [void]$categories.Add("Other")
            $unrecognized.Add($m)
        }
    }
    [pscustomobject]@{
        Categories   = $categories
        Unrecognized = $unrecognized
    }
}

function Get-LikelyCause {
    param([string[]]$Methods, [System.Collections.Generic.HashSet[string]]$Categories)

    if ($Methods.Count -eq 0) { return 'No methods registered' }

    $eligibleCount = @($Categories | Where-Object { $_ -in $SsprEligibleCategories }).Count
    $hasOnlyExcluded = ($eligibleCount -eq 0) -and ($Categories.Count -gt 0)

    if ($hasOnlyExcluded) {
        $excludedPresent = @($Categories | Where-Object { $_ -in @('FIDO2', 'WindowsHello', 'Passkey') })
        if ($excludedPresent.Count -gt 0) {
            return "Only $($excludedPresent -join '/') registered - not usable for SSPR"
        }
        return 'Only non-SSPR-eligible methods registered'
    }

    if ($eligibleCount -eq 1) {
        return 'Only one SSPR-eligible method category registered (policy needs more)'
    }

    return 'Registered categories look sufficient by this script''s count; check the tenant''s exact required-method number and, for admin accounts, the stricter two-gate policy'
}

#endregion

#region Module check

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Warning "Module 'Microsoft.Graph.Authentication' not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
    exit 1
}
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

#endregion

#region Connect

$scopes = @('AuditLog.Read.All')
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

#region Fetch authentication method registration details

Write-Host 'Fetching authentication method registration details...' -ForegroundColor Gray
Write-Host '(Needs the Reports Reader, Security Reader, Security Administrator, or Global Reader role in addition to the AuditLog.Read.All scope.)' -ForegroundColor Gray

$details = [System.Collections.Generic.List[object]]::new()

try {
    $uri = 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999'
    if (-not $IncludeAllUsers) {
        $uri = 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999&$filter=isSsprEnabled eq true'
    }
    do {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        foreach ($d in $resp.value) { $details.Add($d) }
        $uri = $resp.'@odata.nextLink'
    } while ($uri)
    Write-Host "  Users retrieved: $($details.Count)" -ForegroundColor Gray
} catch {
    Write-Warning "Could not read authentication method registration details: $($_.ToString())"
    Write-Warning "If this is a 403, confirm the signed-in account holds Reports Reader (or a higher role listed above) - the Graph scope consent alone is not sufficient for this report."
    exit 1
}

if ($details.Count -eq 0) {
    Write-Warning 'No users returned. If you expected results, check that SSPR registration/enablement is actually configured in this tenant, or re-run with -IncludeAllUsers.'
}

#endregion

#region Categorize and build report rows

$notCapableRows = @()
$durabilityRows = @()

foreach ($d in $details) {
    if (-not $d.isSsprEnabled) { continue }

    $methods = @($d.methodsRegistered)
    $catResult = Get-MethodCategories -Methods $methods
    $categories = $catResult.Categories

    if (-not $d.isSsprCapable) {
        $cause = Get-LikelyCause -Methods $methods -Categories $categories
        $notCapableRows += [pscustomobject]@{
            UserPrincipalName = $d.userPrincipalName
            DisplayName       = $d.userDisplayName
            IsAdmin           = [bool]$d.isAdmin
            UserType          = $d.userType
            MethodsRaw        = $methods
            Categories        = @($categories)
            Unrecognized      = @($catResult.Unrecognized)
            LikelyCause       = $cause
        }
    } elseif ($categories.Contains('MobilePhone') -or $categories.Contains('OfficePhone')) {
        # Capable today, but SMS/voice is among the registered categories keeping them
        # that way. Not a problem today - a forward-looking flag for the Feb/Jul 2027
        # Microsoft-provided SMS/voice retirement covered in the blog post.
        $durabilityRows += [pscustomobject]@{
            UserPrincipalName = $d.userPrincipalName
            DisplayName       = $d.userDisplayName
            IsAdmin           = [bool]$d.isAdmin
            Categories        = @($categories)
        }
    }
}

$notCapableRows = $notCapableRows | Sort-Object @{Expression = { -not $_.IsAdmin }}, DisplayName
$durabilityRows = $durabilityRows | Sort-Object @{Expression = { -not $_.IsAdmin }}, DisplayName

$ssprEnabledCount = @($details | Where-Object { $_.isSsprEnabled }).Count
$notCapableAdminCount = @($notCapableRows | Where-Object { $_.IsAdmin }).Count

Write-Host "  SSPR-enabled users: $ssprEnabledCount | Not SSPR-capable: $($notCapableRows.Count) (of which admin: $notCapableAdminCount) | Durability watch (SMS/voice): $($durabilityRows.Count)" -ForegroundColor Gray

#endregion

#region Build HTML

$generatedAt = Get-Date -Format 'yyyy-MM-dd HH:mm'

$CategoryLabels = @{
    'AuthenticatorOrOATH' = 'Authenticator/OATH'
    'MobilePhone'         = 'Mobile phone'
    'OfficePhone'         = 'Office phone'
    'Email'               = 'Email OTP'
    'SecurityQuestion'    = 'Security questions'
    'FIDO2'               = 'FIDO2'
    'WindowsHello'        = 'Windows Hello'
    'Passkey'             = 'Passkey'
    'Other'               = 'Other'
}

function Format-CategoryBadges {
    param([string[]]$Categories)
    if (-not $Categories -or $Categories.Count -eq 0) { return '<span class="badge badge-gray">None</span>' }
    ($Categories | Sort-Object | ForEach-Object {
        $cls = switch ($_) {
            'AuthenticatorOrOATH' { 'badge-blue' }
            'MobilePhone'         { 'badge-yellow' }
            'OfficePhone'         { 'badge-yellow' }
            'Email'               { 'badge-blue' }
            'SecurityQuestion'    { 'badge-yellow' }
            'FIDO2'               { 'badge-red' }
            'WindowsHello'        { 'badge-red' }
            'Passkey'             { 'badge-red' }
            default               { 'badge-gray' }
        }
        $label = if ($CategoryLabels.ContainsKey($_)) { $CategoryLabels[$_] } else { $_ }
        "<span class=`"badge $cls`">$(ConvertTo-HtmlSafe $label)</span>"
    }) -join ' '
}

$notCapableRowsHtml = ''
if ($notCapableRows.Count -eq 0) {
    $notCapableRowsHtml = '<tr><td colspan="5" class="empty">No SSPR-enabled users found without SSPR capability.</td></tr>'
} else {
    foreach ($row in $notCapableRows) {
        $adminBadge = if ($row.IsAdmin) { '<span class="badge badge-red">Admin</span>' } else { '' }
        $notCapableRowsHtml += "
        <tr>
          <td>
            <span class=`"app-name`">$(ConvertTo-HtmlSafe $row.DisplayName) $adminBadge</span>
            <span class=`"app-id`">$(ConvertTo-HtmlSafe $row.UserPrincipalName)</span>
          </td>
          <td>$(Format-CategoryBadges $row.Categories)</td>
          <td>$($row.MethodsRaw.Count)</td>
          <td>$(ConvertTo-HtmlSafe $row.LikelyCause)</td>
        </tr>"
    }
}

$durabilityRowsHtml = ''
if ($durabilityRows.Count -eq 0) {
    $durabilityRowsHtml = '<tr><td colspan="3" class="empty">No SSPR-capable users depend on SMS or voice call.</td></tr>'
} else {
    foreach ($row in $durabilityRows) {
        $adminBadge = if ($row.IsAdmin) { '<span class="badge badge-red">Admin</span>' } else { '' }
        $durabilityRowsHtml += "
        <tr>
          <td>
            <span class=`"app-name`">$(ConvertTo-HtmlSafe $row.DisplayName) $adminBadge</span>
            <span class=`"app-id`">$(ConvertTo-HtmlSafe $row.UserPrincipalName)</span>
          </td>
          <td>$(Format-CategoryBadges $row.Categories)</td>
        </tr>"
    }
}

$notCapableColor = if ($notCapableRows.Count -gt 0) { 'red' } else { 'green' }
$adminColor      = if ($notCapableAdminCount -gt 0) { 'red' } else { 'green' }
$durabilityColor = if ($durabilityRows.Count -gt 0) { 'yellow' } else { 'green' }

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SSPR Method Coverage Report - $tenantDisplay</title>
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

    .summary{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:8px}
    .card{background:#161616;border:1px solid #262626;border-radius:4px;padding:16px 20px}
    .card-value{font-size:28px;font-weight:700;line-height:1.1;margin-bottom:4px}
    .card-label{font-size:10px;color:#524f4c;text-transform:uppercase;letter-spacing:0.06em}
    .red{color:#e03030} .yellow{color:#fbbf24} .green{color:#4ade80} .gray{color:#524f4c} .blue{color:#60a5fa}

    .table-wrap{background:#161616;border:1px solid #262626;border-radius:4px;overflow:hidden;margin-bottom:4px}
    table{width:100%;border-collapse:collapse}
    th{background:#1e1e1e;color:#524f4c;font-size:10px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;padding:10px 16px;text-align:left;border-bottom:1px solid #262626}
    td{padding:12px 16px;border-bottom:1px solid #1d1d1d;vertical-align:top;color:#f0ece4}
    tr:last-child td{border-bottom:none}
    tr:hover td{background:#1a1a1a}

    .app-name{display:block;font-weight:600}
    .app-id{display:block;font-size:11px;color:#524f4c;font-family:'Courier New',monospace;margin-top:2px}

    td.empty{color:#524f4c;font-style:italic;padding:20px 16px;text-align:center}

    .badge{display:inline-block;font-size:10px;font-weight:700;letter-spacing:0.06em;text-transform:uppercase;padding:2px 7px;border-radius:2px;margin:1px}
    .badge-red   {background:rgba(224,48,48,.12);color:#f07070;border:1px solid rgba(224,48,48,.25)}
    .badge-yellow{background:rgba(251,191,36,.10);color:#fbbf24;border:1px solid rgba(251,191,36,.25)}
    .badge-green {background:rgba(74,222,128,.10);color:#4ade80;border:1px solid rgba(74,222,128,.25)}
    .badge-blue  {background:rgba(96,165,250,.10);color:#60a5fa;border:1px solid rgba(96,165,250,.25)}
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
  <span class="header-title">SSPR Method Coverage Report</span>
  <div class="header-meta">
    <strong>$tenantDisplay</strong>
    Generated $generatedAt
  </div>
</header>

<div class="container">

  <h1>MC1325414 Coverage Check</h1>
  <p class="subtitle">SSPR-enabled users who aren't actually SSPR-capable today, why, and who's capable only through a method Microsoft is retiring in 2027.</p>
  <p class="caveat">isSsprCapable is Microsoft's own live policy evaluation, read directly from the Graph authentication methods report, not re-derived by this script. The "Likely cause" and category badges are this script's own best-effort explanation, based on a manual mapping from the raw methodsRegistered values to the categories described in the linked blog post. An unrecognized method value is shown as an "Other" badge rather than guessed at. This script cannot tell whether a registered phone number or email came from directory sync versus genuine user registration, so it cannot detect the November 7 directory-sourced-fallback change specifically. Re-run after that change reaches your tenant for a current picture. Admin accounts are flagged, not specially evaluated: Microsoft Entra administrator roles are subject to the separate, stricter SSPR two-gate policy, which this script does not model.</p>

  <h2>Summary</h2>
  <div class="summary">
    <div class="card">
      <div class="card-value blue">$ssprEnabledCount</div>
      <div class="card-label">SSPR-enabled users</div>
    </div>
    <div class="card">
      <div class="card-value $notCapableColor">$($notCapableRows.Count)</div>
      <div class="card-label">Not SSPR-capable today</div>
    </div>
    <div class="card">
      <div class="card-value $adminColor">$notCapableAdminCount</div>
      <div class="card-label">...of which admin accounts</div>
    </div>
    <div class="card">
      <div class="card-value $durabilityColor">$($durabilityRows.Count)</div>
      <div class="card-label">Durability watch (SMS/voice)</div>
    </div>
  </div>

  <h2>Not SSPR-capable today</h2>
  <div class="table-wrap">
    <table>
      <thead><tr>
        <th style="width:28%">User</th>
        <th style="width:26%">Registered categories</th>
        <th style="width:10%">Methods</th>
        <th>Likely cause</th>
      </tr></thead>
      <tbody>$notCapableRowsHtml</tbody>
    </table>
  </div>

  <h2>Durability watch: capable today via SMS or voice</h2>
  <p class="note">Not a problem today. Microsoft-provided SMS/voice delivery retires February 1, 2027 for most users, July 1, 2027 for Global Administrators and external users (see the blog post). Plan a follow-up migration for these users ahead of that date.</p>
  <div class="table-wrap">
    <table>
      <thead><tr>
        <th style="width:50%">User</th>
        <th>Registered categories</th>
      </tr></thead>
      <tbody>$durabilityRowsHtml</tbody>
    </table>
  </div>

</div>

<footer>
  <div class="container" style="padding:0">
    <a href="https://learn.microsoft.com/en-us/graph/api/resources/userregistrationdetails" target="_blank">Microsoft Learn - userRegistrationDetails resource</a>
    &nbsp;&middot;&nbsp;
    <a href="https://tenantwizards.com/blog/sspr-registered-methods-november-2026" target="_blank">tenantwizards.com</a>
  </div>
</footer>

</body>
</html>
"@

#endregion

#region Save and open

$timestamp  = Get-Date -Format 'yyyyMMdd-HHmm'
$reportFile = Join-Path $OutputPath "TW-SSPRCoverage-Report-$timestamp.html"

[System.IO.File]::WriteAllText($reportFile, $html, [System.Text.UTF8Encoding]::new($false))

Write-Host ""
Write-Host "Report saved: $reportFile" -ForegroundColor Cyan

if (-not $NoOpen) { Start-Process $reportFile }

#endregion

Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
