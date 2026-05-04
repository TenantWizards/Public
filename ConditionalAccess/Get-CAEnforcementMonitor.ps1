#Requires -Version 5.1

<#
.SYNOPSIS
    Monitors sign-in logs for Conditional Access blocks and new MFA requirements
    following the Microsoft CA enforcement change (May 13, 2026).

.DESCRIPTION
    After May 13, 2026, CA policies targeting "All resources" with app exclusions
    enforce consistently for sign-ins that previously bypassed enforcement.

    This script:
      1. Identifies which CA policies are in scope (targeting all cloud apps with
         specific app exclusions) -- handles multiple policies.
      2. Queries sign-in logs with full pagination and filters to events caused by
         those policies only, grouped by resource (the target CA policies protect).
      3. Post-May 13: cross-checks against the 7-day window before enforcement to
         filter out sign-ins that were already being enforced before the change.
    Results are exported as an HTML report.

.PARAMETER TenantId
    Optional. Specify the tenant ID to connect to a specific tenant.

.PARAMETER DaysBack
    Number of days to look back. Default: 7.

.PARAMETER Since
    Specific start date (overrides DaysBack). Format: yyyy-MM-dd.

.PARAMETER OutputPath
    Optional. Path for the HTML report. Defaults to the temp folder.

.PARAMETER EnforcementDate
    Optional. The date enforcement started. Used for the delta check boundary and report labels. Default: 2026-05-13.

.PARAMETER NoOpen
    Switch. Do not automatically open the report in the browser.

.EXAMPLE
    .\Get-CAEnforcementMonitor.ps1

.EXAMPLE
    .\Get-CAEnforcementMonitor.ps1 -Since "2026-05-13"

.EXAMPLE
    .\Get-CAEnforcementMonitor.ps1 -DaysBack 14 -TenantId "contoso.onmicrosoft.com"

.EXAMPLE
    .\Get-CAEnforcementMonitor.ps1 -EnforcementDate "2026-06-01"

.NOTES
    Required Graph permissions (delegated):
        Policy.Read.All
        AuditLog.Read.All
        Application.Read.All   (recommended - resolves app display names)

    Required modules:
        Microsoft.Graph.Authentication

    Sign-in logs require an Entra ID P1 or P2 license.

    Author: Tenant Wizards (tenantwizards.nl)

.LINK
    https://tenantwizards.nl/blog/conditional-access-changes-may-13
#>

[CmdletBinding()]
param (
    [Parameter()] [string]$TenantId,
    [Parameter()] [int]$DaysBack = 7,
    [Parameter()] [string]$Since,
    [Parameter()] [string]$OutputPath = $env:TEMP,
    [Parameter()] [datetime]$EnforcementDate = [datetime]'2026-05-13',
    [Parameter()] [switch]$NoOpen
)

$ErrorActionPreference = 'Stop'

#region Helpers

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if (-not $Text) { return '' }
    $Text -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
}

function Format-DateCell {
    param($Value)
    if (-not $Value) { return '-' }
    try { ([datetime]$Value).ToString('yyyy-MM-dd HH:mm') } catch { $Value }
}

function Invoke-MgBatchPaged {
    <#
    Fires multiple independent Graph queries simultaneously using JSON batching.
    Each round sends all pending requests in one HTTP call (up to 20 per batch).
    Queries that return @odata.nextLink are re-queued for the next round until
    all pages for all queries are exhausted.

    $Queries : @( @{ Id = 'name'; Uri = '/v1.0/...' }, ... )  (relative URLs)
    Returns  : @{ Results = @{ Id = @(items) }; Errors = @{ Id = 'msg' } }
    #>
    param([hashtable[]]$Queries)

    $results = @{}
    $errors  = @{}
    foreach ($q in $Queries) { $results[$q.Id] = @() }

    $pending = @($Queries)
    $round   = 0

    while ($pending.Count -gt 0) {
        $round++
        $chunk   = @($pending[0..[Math]::Min(19, $pending.Count - 1)])
        $pending = @($pending | Select-Object -Skip 20)

        # Normalize URIs: strip version prefix — beta/$batch resolves relative to beta root
        $batchBody = @{
            requests = @($chunk | ForEach-Object {
                $uri = $_.Uri -replace '^/(v1\.0|beta)/', '/'
                @{ id = $_.Id; method = 'GET'; url = $uri }
            })
        } | ConvertTo-Json -Depth 10 -Compress

        Write-Host "  Batch round $round ($($chunk.Count) queries in parallel)..." -ForegroundColor Gray

        $batchResp = Invoke-MgGraphRequest -Method POST `
            -Uri 'https://graph.microsoft.com/beta/$batch' `
            -Body $batchBody `
            -ContentType 'application/json' `
            -ErrorAction Stop

        foreach ($item in @($batchResp.responses)) {
            $qId = $item.id
            if ($item.status -eq 200) {
                $page = @($item.body.value)
                $results[$qId] += $page
                Write-Host "    $qId +$($page.Count) (total $($results[$qId].Count))" -ForegroundColor DarkGray
                $next = $item.body['@odata.nextLink']
                if ($next) {
                    $relUri  = $next -replace '^https://graph\.microsoft\.com/(v1\.0|beta)', ''
                    $pending += @(@{ Id = $qId; Uri = $relUri })
                }
            } else {
                $errMsg = if ($item.body.error.message) { $item.body.error.message } else { "status $($item.status)" }
                $errors[$qId] = "HTTP $($item.status): $errMsg"
                Write-Host "    $qId error: $($errors[$qId])" -ForegroundColor Yellow
            }
        }
    }

    return @{ Results = $results; Errors = $errors }
}

function Get-ResourceLabel {
    param($Entry)
    if ($Entry.resourceDisplayName) { return $Entry.resourceDisplayName }
    return $Entry.appDisplayName
}

function Build-ResourceCards {
    param([array]$SignIns, [string]$ResultType, [array]$PolicyIds, [string]$ErrMsg, [bool]$NoPolicies, [bool]$HasPolicyError)
    if ($ErrMsg)                               { return "<div class=`"box-notice`">$(ConvertTo-HtmlSafe $ErrMsg)</div>" }
    if ($NoPolicies -and -not $HasPolicyError)  { return '<div class="box-empty">No relevant policies in scope.</div>' }
    if (-not $SignIns -or $SignIns.Count -eq 0) {
        $msg = if ($ResultType -eq 'failure') { 'No CA failures from relevant policies in this period.' } else { 'No CA-enforced MFA sign-ins from relevant policies in this period.' }
        return "<div class=`"box-empty`">$msg</div>"
    }
    $out     = ''
    $grouped = $SignIns | Group-Object { Get-ResourceLabel $_ } | Sort-Object Count -Descending
    foreach ($group in $grouped) {
        $uniqueUsers = @($group.Group | ForEach-Object { $_.userPrincipalName } | Where-Object { $_ } | Sort-Object -Unique)
        $lastSeen    = Format-DateCell ($group.Group | Sort-Object createdDateTime -Descending | Select-Object -First 1).createdDateTime
        $polNames    = @(
            $group.Group | ForEach-Object { @($_.appliedConditionalAccessPolicies) } |
            Where-Object { $_.result -eq $ResultType -and $PolicyIds -contains $_.id } |
            ForEach-Object { $_.displayName } | Where-Object { $_ } | Sort-Object -Unique
        )
        $polTagsHtml = ($polNames | ForEach-Object { "<span class=`"ptag`">$(ConvertTo-HtmlSafe $_)</span>" }) -join ' '
        $userLabel   = if ($uniqueUsers.Count -eq 1) { '1 user' } else { "$($uniqueUsers.Count) users" }
        if ($ResultType -eq 'failure') {
            $thead = '<tr><th>User</th><th>Client</th><th>Time</th><th>Failure reason</th></tr>'
            $rows  = ($group.Group | Sort-Object createdDateTime -Descending | ForEach-Object {
                "<tr><td>$(ConvertTo-HtmlSafe $_.userPrincipalName)</td><td>$(ConvertTo-HtmlSafe $_.clientAppUsed)</td><td>$(Format-DateCell $_.createdDateTime)</td><td>$(ConvertTo-HtmlSafe $_.status.failureReason)</td></tr>"
            }) -join ''
        } else {
            $thead = '<tr><th>User</th><th>Client</th><th>Time</th></tr>'
            $rows  = ($group.Group | Sort-Object createdDateTime -Descending | ForEach-Object {
                "<tr><td>$(ConvertTo-HtmlSafe $_.userPrincipalName)</td><td>$(ConvertTo-HtmlSafe $_.clientAppUsed)</td><td>$(Format-DateCell $_.createdDateTime)</td></tr>"
            }) -join ''
        }
        $out += "
<div class=`"res-card`">
  <div class=`"res-hdr`" onclick=`"toggleCard(this)`">
    <div class=`"rh-l`"><span class=`"res-name`">$(ConvertTo-HtmlSafe $group.Name)</span><span class=`"cnt-badge`">$($group.Count)</span><span class=`"usr-label`">$userLabel</span></div>
    <div class=`"rh-r`">$polTagsHtml<span class=`"ts`">$lastSeen</span><span class=`"toggle-ic`">+</span></div>
  </div>
  <div class=`"res-body`"><table><thead>$thead</thead><tbody>$rows</tbody></table></div>
</div>"
    }
    return $out
}

#endregion

#region Module check

if (-not (Get-InstalledModule -Name 'Microsoft.Graph.Authentication' -ErrorAction SilentlyContinue)) {
    Write-Warning "Module 'Microsoft.Graph.Authentication' not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
    exit 1
}
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

#endregion

#region Connect

$connectParams = @{ Scopes = @('Policy.Read.All', 'AuditLog.Read.All', 'Application.Read.All'); NoWelcome = $true }
if ($TenantId) { $connectParams['TenantId'] = $TenantId }

Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Gray
Connect-MgGraph @connectParams | Out-Null

$ctx = Get-MgContext
$tenantDisplay = $ctx.TenantId
try {
    Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction SilentlyContinue
    $org = Get-MgOrganization -ErrorAction SilentlyContinue
    if ($org) { $tenantDisplay = "$($org.DisplayName) ($($ctx.TenantId))" }
} catch {}

Write-Host "Connected: $($ctx.Account) - $tenantDisplay" -ForegroundColor Gray

#endregion

#region Date range

$startDate = if ($Since) {
    [datetime]::ParseExact($Since, 'yyyy-MM-dd', $null)
} else {
    (Get-Date).AddDays(-$DaysBack)
}

$startUtc    = $startDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$periodLabel = if ($Since) { "since $Since" } else { "last $DaysBack days" }

Write-Host "Period: $periodLabel (from $startUtc)" -ForegroundColor Gray

#endregion

#region Collect relevant CA policies

Write-Host 'Fetching Conditional Access policies...' -ForegroundColor Gray

$allPolicies      = @()
$relevantPolicies = @()
$policyError      = $null

try {
    $policyBatch = Invoke-MgBatchPaged -Queries @(
        @{ Id = 'policies'; Uri = '/v1.0/identity/conditionalAccess/policies?$top=999' }
    )
    if ($policyBatch.Errors['policies']) { throw $policyBatch.Errors['policies'] }
    $allPolicies = @($policyBatch.Results['policies'])

    $relevantPolicies = @(
        $allPolicies | Where-Object {
            $apps        = $_.conditions.applications
            $includeApps = @($apps.includeApplications)
            $excludeApps = @($apps.excludeApplications)
            ($includeApps -contains 'All') -and ($excludeApps.Count -gt 0)
        }
    )
    Write-Host "  Total policies: $($allPolicies.Count) | In scope: $($relevantPolicies.Count)" -ForegroundColor Gray
} catch {
    $policyError = "Could not retrieve CA policies: $_"
    Write-Host "  Unavailable: $policyError" -ForegroundColor Yellow
}

$relevantPolicyIds = @($relevantPolicies | ForEach-Object { $_.id })

$allExcludedAppIds = @(
    $relevantPolicies |
    ForEach-Object { @($_.conditions.applications.excludeApplications) } |
    Sort-Object -Unique
)

Write-Host "  Excluded app IDs across all relevant policies: $($allExcludedAppIds.Count)" -ForegroundColor Gray

#endregion

#region Resolve app names

$appNameCache = @{}

function Get-AppName {
    param([string]$AppId)
    if (-not $AppId) { return '' }
    if ($appNameCache.ContainsKey($AppId)) { return $appNameCache[$AppId] }
    try {
        $uri    = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$AppId'&`$select=displayName&`$top=1"
        $spResp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction SilentlyContinue
        $name   = if ($spResp -and @($spResp.value).Count -gt 0) {
            @($spResp.value)[0].displayName
        } else { $AppId }
    } catch { $name = $AppId }
    $appNameCache[$AppId] = $name
    return $name
}

foreach ($appId in $allExcludedAppIds) { Get-AppName $appId | Out-Null }

#endregion

#region Query sign-in logs (paged, post-filtered to relevant policies)

# resourceDisplayName = the resource CA policies protect (target of IncludeApplications)
# appDisplayName      = the client application that initiated the sign-in
$select = 'appDisplayName,resourceDisplayName,userPrincipalName,createdDateTime,conditionalAccessStatus,status,clientAppUsed,appliedConditionalAccessPolicies'

$caFailures   = @()
$mfaSignIns   = @()
$caFailError  = $null
$mfaSignError = $null

if ($relevantPolicies.Count -eq 0 -and -not $policyError) {
    Write-Host 'No policies in scope - skipping sign-in log queries.' -ForegroundColor Gray
} else {

    # CA failures + MFA sign-ins: queried simultaneously via Graph batch
    Write-Host 'Fetching CA failures and MFA sign-ins (parallel batch, all pages)...' -ForegroundColor Gray

    $failFilter = "conditionalAccessStatus eq 'failure' and createdDateTime ge $startUtc"
    $mfaFilter  = "authenticationRequirement eq 'multiFactorAuthentication' and conditionalAccessStatus eq 'success' and createdDateTime ge $startUtc"

    try {
        $mainBatch = Invoke-MgBatchPaged -Queries @(
            @{ Id = 'caFail'; Uri = "/v1.0/auditLogs/signIns?`$filter=$failFilter&`$top=999&`$select=$select&`$orderby=createdDateTime desc" }
            @{ Id = 'mfa';    Uri = "/beta/auditLogs/signIns?`$filter=$mfaFilter&`$top=999&`$select=$select&`$orderby=createdDateTime desc" }
        )
    } catch {
        $caFailError  = "Batch request failed: $_"
        $mfaSignError = $caFailError
        Write-Host "  Batch error: $_" -ForegroundColor Yellow
    }

    if (-not $caFailError -and -not $mfaSignError) {
        if ($mainBatch.Errors['caFail']) {
            $errMsg      = $mainBatch.Errors['caFail']
            $caFailError = if ($errMsg -match '403|Forbidden') {
                'AuditLog.Read.All permission not granted. Go to Entra > Enterprise applications > Microsoft Graph Command Line Tools > Permissions > Grant admin consent.'
            } elseif ($errMsg -match 'license|P1|P2|Premium') {
                'Sign-in logs require an Entra ID P1 or P2 license.'
            } else { "Could not retrieve sign-in logs: $errMsg" }
            Write-Host "  CA failures unavailable: $caFailError" -ForegroundColor Yellow
        } else {
            $rawFail    = @($mainBatch.Results['caFail'])
            $caFailures = @(
                $rawFail | Where-Object {
                    $applied = @($_.appliedConditionalAccessPolicies)
                    $match   = @($applied | Where-Object { $_.result -eq 'failure' -and $relevantPolicyIds -contains $_.id })
                    $match.Count -gt 0
                }
            )
            Write-Host "  Raw failures: $($rawFail.Count) | From relevant policies: $($caFailures.Count)" -ForegroundColor Gray
        }

        if ($mainBatch.Errors['mfa']) {
            $errMsg       = $mainBatch.Errors['mfa']
            $mfaSignError = if ($errMsg -match '403|Forbidden') {
                'AuditLog.Read.All permission not granted.'
            } elseif ($errMsg -match 'license|P1|P2|Premium') {
                'Sign-in logs require an Entra ID P1 or P2 license.'
            } else { "Could not retrieve sign-in logs: $errMsg" }
            Write-Host "  MFA sign-ins unavailable: $mfaSignError" -ForegroundColor Yellow
        } else {
            $rawMfa     = @($mainBatch.Results['mfa'])
            $mfaSignIns = @(
                $rawMfa | Where-Object {
                    $applied = @($_.appliedConditionalAccessPolicies)
                    $match   = @($applied | Where-Object { $_.result -eq 'success' -and $relevantPolicyIds -contains $_.id })
                    $match.Count -gt 0
                }
            )
            Write-Host "  Raw MFA sign-ins: $($rawMfa.Count) | From relevant policies: $($mfaSignIns.Count)" -ForegroundColor Gray
        }
    }
}

#endregion

#region Delta check — filter out pre-existing enforcement (post-May 13 only)

$deltaApplied      = $false
$mfaFilteredCount  = 0
$failFilteredCount = 0

if ((Get-Date) -ge $EnforcementDate -and ($mfaSignIns.Count -gt 0 -or $caFailures.Count -gt 0)) {
    $deltaApplied      = $true
    $beforeWindowEnd   = $EnforcementDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $beforeWindowStart = $EnforcementDate.AddDays(-7).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

    Write-Host 'Delta check: querying before-period to identify pre-existing enforcement...' -ForegroundColor Gray

    # Both before-period queries run simultaneously via Graph batch.
    # Compare on resourceDisplayName: the resource CA policies target.
    $beforeMfaFilter  = "authenticationRequirement eq 'multiFactorAuthentication' and conditionalAccessStatus eq 'success' and createdDateTime ge $beforeWindowStart and createdDateTime lt $beforeWindowEnd"
    $beforeFailFilter = "conditionalAccessStatus eq 'failure' and createdDateTime ge $beforeWindowStart and createdDateTime lt $beforeWindowEnd"

    $preExistingMfaResources  = @()
    $preExistingFailResources = @()

    try {
        $beforeBatch = Invoke-MgBatchPaged -Queries @(
            @{ Id = 'beforeMfa';  Uri = "/beta/auditLogs/signIns?`$filter=$beforeMfaFilter&`$top=999&`$select=$select" }
            @{ Id = 'beforeFail'; Uri = "/v1.0/auditLogs/signIns?`$filter=$beforeFailFilter&`$top=999&`$select=$select" }
        )

        if ($beforeBatch.Errors['beforeMfa']) {
            Write-Host "  Before-period MFA query failed (delta check skipped for MFA): $($beforeBatch.Errors['beforeMfa'])" -ForegroundColor Yellow
        } else {
            $preExistingMfaResources = @(
                @($beforeBatch.Results['beforeMfa']) | Where-Object {
                    $applied = @($_.appliedConditionalAccessPolicies)
                    $match   = @($applied | Where-Object { $_.result -eq 'success' -and $relevantPolicyIds -contains $_.id })
                    $match.Count -gt 0
                } | ForEach-Object { Get-ResourceLabel $_ } | Where-Object { $_ } | Sort-Object -Unique
            )
            Write-Host "  Before-period MFA resources already enforced: $($preExistingMfaResources.Count)" -ForegroundColor Gray
        }

        if ($beforeBatch.Errors['beforeFail']) {
            Write-Host "  Before-period failure query failed (delta check skipped for failures): $($beforeBatch.Errors['beforeFail'])" -ForegroundColor Yellow
        } else {
            $preExistingFailResources = @(
                @($beforeBatch.Results['beforeFail']) | Where-Object {
                    $applied = @($_.appliedConditionalAccessPolicies)
                    $match   = @($applied | Where-Object { $_.result -eq 'failure' -and $relevantPolicyIds -contains $_.id })
                    $match.Count -gt 0
                } | ForEach-Object { Get-ResourceLabel $_ } | Where-Object { $_ } | Sort-Object -Unique
            )
            Write-Host "  Before-period CA failure resources already blocked: $($preExistingFailResources.Count)" -ForegroundColor Gray
        }
    } catch {
        Write-Host "  Before-period batch query failed (delta check skipped): $_" -ForegroundColor Yellow
    }

    # Filter: exclude resources where enforcement was already in place before May 13
    $beforeMfa    = $mfaSignIns.Count
    $mfaSignIns   = @($mfaSignIns | Where-Object { $preExistingMfaResources -notcontains (Get-ResourceLabel $_) })
    $mfaFilteredCount = $beforeMfa - $mfaSignIns.Count

    $beforeFail        = $caFailures.Count
    $caFailures        = @($caFailures | Where-Object { $preExistingFailResources -notcontains (Get-ResourceLabel $_) })
    $failFilteredCount = $beforeFail - $caFailures.Count

    Write-Host "  Filtered out (pre-existing): $mfaFilteredCount MFA, $failFilteredCount failures" -ForegroundColor Gray
}

# Deduplicate: same user + resource + exact timestamp = one entry
$caFailures = @($caFailures | Group-Object { "$($_.userPrincipalName)|$(Get-ResourceLabel $_)|$($_.createdDateTime)" } | ForEach-Object { $_.Group[0] })
$mfaSignIns = @($mfaSignIns | Group-Object { "$($_.userPrincipalName)|$(Get-ResourceLabel $_)|$($_.createdDateTime)" } | ForEach-Object { $_.Group[0] })

#endregion

#region Build HTML

$generatedAt = Get-Date -Format 'yyyy-MM-dd HH:mm'

$affectedResources = @(
    @($caFailures) + @($mfaSignIns) |
    ForEach-Object { Get-ResourceLabel $_ } |
    Where-Object { $_ } | Sort-Object -Unique
)
$affectedUsers = @(
    @($caFailures) + @($mfaSignIns) |
    ForEach-Object { $_.userPrincipalName } | Where-Object { $_ } |
    Sort-Object -Unique
)

$enabledCount  = @($relevantPolicies | Where-Object { $_.state -eq 'enabled' }).Count
$reportCount   = @($relevantPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' }).Count
$disabledCount = @($relevantPolicies | Where-Object { $_.state -eq 'disabled' }).Count

# ---- Policy overview rows ----
$policyRowsHtml = ''
if ($policyError) {
    $policyRowsHtml = "<tr><td colspan=`"3`" class=`"notice`">$(ConvertTo-HtmlSafe $policyError)</td></tr>"
} elseif ($relevantPolicies.Count -eq 0) {
    $policyRowsHtml = '<tr><td colspan="3" class="empty">No CA policies with this configuration found. Your tenant is not in scope for the May 13 enforcement change.</td></tr>'
} else {
    $stateOrder = @{ 'enabled' = 0; 'enabledForReportingButNotEnforced' = 1; 'disabled' = 2 }
    $sortedPolicies = $relevantPolicies | Sort-Object { if ($stateOrder.ContainsKey($_.state)) { $stateOrder[$_.state] } else { 3 } }

    $currentState = $null
    foreach ($policy in $sortedPolicies) {
        $stateLabel = switch ($policy.state) {
            'enabled'                           { 'Enabled' }
            'enabledForReportingButNotEnforced' { 'Report only' }
            'disabled'                          { 'Disabled' }
            default                             { $policy.state }
        }
        $badgeClass = switch ($policy.state) {
            'enabled'                           { 'badge-red' }
            'enabledForReportingButNotEnforced' { 'badge-yellow' }
            default                             { 'badge-gray' }
        }

        if ($policy.state -ne $currentState) {
            $currentState    = $policy.state
            $policyRowsHtml += "<tr class=`"grp-hdr`"><td colspan=`"3`">$stateLabel</td></tr>"
        }

        $excludedApps = @($policy.conditions.applications.excludeApplications)
        $appListHtml  = ''
        foreach ($appId in $excludedApps) {
            $appName      = Get-AppName $appId
            $appListHtml += "<li>$(ConvertTo-HtmlSafe $appName)</li>"
        }

        $policyRowsHtml += "
        <tr>
          <td>
            <span class=`"policy-name`">$(ConvertTo-HtmlSafe $policy.displayName)</span>
            <span class=`"policy-id`">$($policy.id)</span>
          </td>
          <td><span class=`"badge $badgeClass`">$stateLabel</span></td>
          <td><ul class=`"app-list`">$appListHtml</ul></td>
        </tr>"
    }
}

# ---- Build sign-in cards ----
$caFailCardsHtml = Build-ResourceCards -SignIns $caFailures -ResultType 'failure' -PolicyIds $relevantPolicyIds -ErrMsg $caFailError -NoPolicies ($relevantPolicies.Count -eq 0) -HasPolicyError ($null -ne $policyError)
$mfaCardsHtml    = Build-ResourceCards -SignIns $mfaSignIns -ResultType 'success' -PolicyIds $relevantPolicyIds -ErrMsg $mfaSignError -NoPolicies ($relevantPolicies.Count -eq 0) -HasPolicyError ($null -ne $policyError)

# ---- Card colors ----
$polColor  = if ($policyError) { 'yellow' } elseif ($relevantPolicies.Count -gt 0) { 'yellow' } else { 'green' }
$failColor = if ($caFailError) { 'yellow' } elseif ($caFailures.Count -gt 0) { 'red' } else { 'green' }
$mfaColor  = if ($mfaSignError) { 'yellow' } elseif ($mfaSignIns.Count -gt 0) { 'yellow' } else { 'green' }
$resColor  = if ($affectedResources.Count -gt 0) { 'yellow' } else { 'gray' }
$userColor = if ($affectedUsers.Count -gt 0) { 'yellow' } else { 'gray' }

$polValue  = if ($policyError) { '?' } else { $relevantPolicies.Count }
$failValue = if ($caFailError) { '?' } else { $caFailures.Count }
$mfaValue  = if ($mfaSignError) { '?' } else { $mfaSignIns.Count }

$deltaNote = if ($deltaApplied) {
    "Delta check applied: $mfaFilteredCount MFA and $failFilteredCount failure sign-ins excluded because they were already enforced before May 13."
} else { '' }

$preEnforcementBanner = if ((Get-Date) -lt $EnforcementDate) { @"
  <div class="pre-banner">
    <strong>Pre-enforcement mode</strong> &mdash; Running before May 13, 2026. Sign-ins shown reflect the current baseline. After May 13, re-run to see what the enforcement change introduced.
  </div>
"@ } elseif ($deltaNote) { @"
  <div class="info-banner">$deltaNote</div>
"@ } else { '' }

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CA Enforcement Monitor - $tenantDisplay</title>
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
    .subtitle{color:#8c8880;font-size:13px;margin-bottom:24px}
    h2{font-size:11px;font-weight:600;color:#524f4c;letter-spacing:0.1em;text-transform:uppercase;margin:40px 0 0}

    /* Banners */
    .pre-banner{background:#1c1a0e;border:1px solid #3d3200;border-left:3px solid #fbbf24;border-radius:4px;padding:12px 16px;margin-bottom:28px;color:#a89060;font-size:13px}
    .pre-banner strong{color:#fbbf24}
    .info-banner{background:#161616;border:1px solid #262626;border-left:3px solid #4ade80;border-radius:4px;padding:12px 16px;margin-bottom:28px;color:#8c8880;font-size:13px}

    /* Summary cards */
    .summary{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:16px 0 0}
    .card{background:#161616;border:1px solid #262626;border-radius:4px;padding:16px 20px}
    .card-value{font-size:28px;font-weight:700;line-height:1.1;margin-bottom:4px}
    .card-label{font-size:10px;color:#524f4c;text-transform:uppercase;letter-spacing:0.06em}
    .red{color:#e03030} .yellow{color:#fbbf24} .green{color:#4ade80} .gray{color:#524f4c}

    /* Policy table */
    .section-note{color:#524f4c;font-size:12px;margin:10px 0 12px}
    .table-wrap{background:#161616;border:1px solid #262626;border-radius:4px;overflow:hidden}
    table{width:100%;border-collapse:collapse}
    th{background:#1e1e1e;color:#524f4c;font-size:10px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;padding:10px 16px;text-align:left;border-bottom:1px solid #262626}
    td{padding:10px 16px;border-bottom:1px solid #1d1d1d;vertical-align:top;color:#f0ece4}
    tr:last-child td{border-bottom:none}
    tr:hover td{background:#1a1a1a}
    tr.grp-hdr td{background:#1e1e1e;color:#524f4c;font-size:10px;font-weight:700;letter-spacing:0.1em;text-transform:uppercase;padding:6px 16px;border-bottom:1px solid #262626}
    tr.grp-hdr:hover td{background:#1e1e1e}
    .policy-name{display:block;font-weight:600}
    .policy-id{display:block;font-size:10px;color:#3a3835;font-family:'Courier New',monospace;margin-top:2px}
    .app-list{list-style:none;padding:0}
    .app-list li{color:#8c8880;font-size:12px;padding:1px 0}
    .app-list li::before{content:'- ';color:#524f4c}
    .badge{display:inline-block;font-size:10px;font-weight:700;letter-spacing:0.06em;text-transform:uppercase;padding:2px 7px;border-radius:2px}
    .badge-red   {background:rgba(224,48,48,.12);color:#f07070;border:1px solid rgba(224,48,48,.25)}
    .badge-yellow{background:rgba(251,191,36,.10);color:#fbbf24;border:1px solid rgba(251,191,36,.25)}
    .badge-gray  {background:rgba(82,79,76,.20);color:#524f4c;border:1px solid rgba(82,79,76,.30)}

    /* Section toolbar */
    .sec-toolbar{display:flex;align-items:baseline;justify-content:space-between;margin:10px 0 12px}
    .sec-toolbar .section-note{margin:0}
    .btn-toggle-all{background:none;border:1px solid #262626;border-radius:2px;color:#524f4c;font-size:11px;padding:3px 10px;cursor:pointer;font-family:inherit}
    .btn-toggle-all:hover{color:#8c8880;border-color:#524f4c}

    /* Resource cards */
    .res-card{background:#161616;border:1px solid #262626;border-radius:4px;margin-bottom:6px;overflow:hidden}
    .res-hdr{display:flex;align-items:center;justify-content:space-between;padding:13px 16px;cursor:pointer;user-select:none;gap:12px}
    .res-hdr:hover{background:#1a1a1a}
    .rh-l{display:flex;align-items:center;gap:10px;flex:1;min-width:0}
    .res-name{font-weight:600;color:#f0ece4;font-size:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .cnt-badge{display:inline-block;font-size:11px;color:#8c8880;background:#1e1e1e;border:1px solid #262626;border-radius:2px;padding:1px 7px;white-space:nowrap;flex-shrink:0}
    .usr-label{font-size:12px;color:#524f4c;white-space:nowrap;flex-shrink:0}
    .rh-r{display:flex;align-items:center;gap:10px;flex-shrink:0}
    .ptag{display:inline-block;font-size:11px;color:#524f4c;background:#1a1a1a;border:1px solid #222;border-radius:2px;padding:1px 7px;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .ts{font-family:'Courier New',monospace;font-size:11px;color:#3a3835;white-space:nowrap}
    .toggle-ic{font-size:18px;color:#3a3835;line-height:1;width:16px;text-align:center;transition:transform 0.15s;flex-shrink:0}
    .res-body{display:none;border-top:1px solid #1d1d1d}
    .res-body.open{display:block}
    .res-body table{width:100%;border-collapse:collapse}
    .res-body th{background:#181818;color:#524f4c;font-size:10px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;padding:8px 16px;text-align:left;border-bottom:1px solid #1d1d1d}
    .res-body td{padding:9px 16px;border-bottom:1px solid #161616;font-size:13px;color:#c8c4bc;vertical-align:middle}
    .res-body tr:last-child td{border-bottom:none}
    .res-body tr:hover td{background:#1a1a1a}

    /* Empty / notice states */
    .box-empty{background:#161616;border:1px solid #262626;border-radius:4px;padding:20px;color:#524f4c;font-style:italic;font-size:13px;text-align:center}
    .box-notice{background:#161616;border:1px solid #262626;border-radius:4px;padding:20px;color:#fbbf24;font-size:13px;text-align:center}

    footer{margin-top:60px;padding:20px 40px;border-top:1px solid #262626;color:#524f4c;font-size:11px}
    footer a{color:#524f4c}
    footer a:hover{color:#8c8880}
  </style>
</head>
<body>

<header class="site-header">
  <div class="logo"><span class="bracket">[</span>TW<span class="bracket">]</span></div>
  <span class="header-divider">|</span>
  <span class="header-title">Conditional Access Enforcement Monitor</span>
  <div class="header-meta">
    <strong>$tenantDisplay</strong>
    $periodLabel &middot; Generated $generatedAt
  </div>
</header>

<div class="container">

  <h1>CA Enforcement Monitor</h1>
  <p class="subtitle">Sign-in activity scoped to policies affected by the May 13, 2026 CA enforcement change. Only policies targeting all cloud apps with app exclusions are included.</p>

$preEnforcementBanner
  <h2>Summary</h2>
  <div class="summary">
    <div class="card"><div class="card-value $polColor">$polValue</div><div class="card-label">Policies in scope</div></div>
    <div class="card"><div class="card-value $failColor">$failValue</div><div class="card-label">CA failures</div></div>
    <div class="card"><div class="card-value $mfaColor">$mfaValue</div><div class="card-label">MFA-required</div></div>
    <div class="card"><div class="card-value $resColor">$($affectedResources.Count)</div><div class="card-label">Affected resources</div></div>
    <div class="card"><div class="card-value $userColor">$($affectedUsers.Count)</div><div class="card-label">Affected users</div></div>
  </div>

  <h2>Policies in scope</h2>
  <p class="section-note">CA policies targeting all cloud apps with one or more app exclusions.</p>
  <div class="table-wrap">
    <table>
      <thead><tr><th style="width:46%">Policy</th><th style="width:13%">State</th><th>Excluded apps</th></tr></thead>
      <tbody>$policyRowsHtml</tbody>
    </table>
  </div>

  <h2>Conditional Access Failures</h2>
  <div class="sec-toolbar">
    <p class="section-note">Sign-ins blocked by a relevant CA policy. Click a row to expand users.</p>
    <button class="btn-toggle-all" onclick="toggleAll('sec-fail', this)">Expand all</button>
  </div>
  <div id="sec-fail">$caFailCardsHtml</div>

  <h2>MFA-Required Sign-ins</h2>
  <div class="sec-toolbar">
    <p class="section-note">Successful sign-ins that required MFA due to a relevant CA policy. Click a row to expand users.</p>
    <button class="btn-toggle-all" onclick="toggleAll('sec-mfa', this)">Expand all</button>
  </div>
  <div id="sec-mfa">$mfaCardsHtml</div>

</div>

<footer>
  <div class="container" style="padding:0">
    <a href="https://techcommunity.microsoft.com/blog/microsoft-entra-blog/upcoming-conditional-access-change-improved-enforcement-for-policies-with-resour/4488925" target="_blank">Microsoft Entra Blog - CA enforcement change</a>
    &nbsp;&middot;&nbsp;
    <a href="https://tenantwizards.nl/blog/conditional-access-changes-may-13" target="_blank">tenantwizards.nl</a>
  </div>
</footer>

<script>
function toggleCard(hdr) {
  var body = hdr.nextElementSibling;
  var ic   = hdr.querySelector('.toggle-ic');
  var open = body.classList.toggle('open');
  ic.style.transform = open ? 'rotate(45deg)' : '';
}
function toggleAll(secId, btn) {
  var cards = document.querySelectorAll('#' + secId + ' .res-body');
  var anyOpen = Array.prototype.some.call(cards, function(c){ return c.classList.contains('open'); });
  Array.prototype.forEach.call(cards, function(c) {
    var ic = c.previousElementSibling.querySelector('.toggle-ic');
    if (anyOpen) { c.classList.remove('open'); ic.style.transform = ''; }
    else         { c.classList.add('open');    ic.style.transform = 'rotate(45deg)'; }
  });
  btn.textContent = anyOpen ? 'Expand all' : 'Collapse all';
}
</script>
</body>
</html>
"@

#endregion

#region Save and open

$timestamp  = Get-Date -Format 'yyyyMMdd-HHmm'
$reportFile = Join-Path $OutputPath "TW-CA-Monitor-$timestamp.html"

[System.IO.File]::WriteAllText($reportFile, $html, [System.Text.UTF8Encoding]::new($false))

Write-Host ''
Write-Host "Report saved: $reportFile" -ForegroundColor Cyan

if (-not $NoOpen) { Start-Process $reportFile }

#endregion

Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
