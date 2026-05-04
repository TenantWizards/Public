# TenantWizards — PowerShell Scripts

PowerShell scripts for Microsoft 365 security and administration. Published by [Tenant Wizards](https://tenantwizards.nl).

## Scripts

### ConditionalAccess

| Script | Description |
|--------|-------------|
| [Get-CAEnforcementReport.ps1](ConditionalAccess/Get-CAEnforcementReport.ps1) | Pre-enforcement audit: checks whether your tenant is affected by the CA enforcement change (MC1223829, May 13 2026). Lists relevant policies and detects legacy authentication sign-ins that will break after enforcement. Outputs an HTML report. |
| [Get-CAEnforcementMonitor.ps1](ConditionalAccess/Get-CAEnforcementMonitor.ps1) | Post-enforcement monitor: queries sign-in logs after May 13 and shows CA failures and new MFA-required sign-ins scoped to affected policies only. Cross-checks against the week before May 13 to filter out pre-existing enforcement. Outputs an HTML report. |

More context: [tenantwizards.nl/blog/conditional-access-changes-may-13](https://tenantwizards.nl/blog/conditional-access-changes-may-13)

## Requirements

- PowerShell 5.1 or PowerShell 7+
- Microsoft Graph PowerShell SDK

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

## Usage

Run scripts directly against your tenant:

```powershell
.\ConditionalAccess\Get-CAEnforcementReport.ps1
.\ConditionalAccess\Get-CAEnforcementMonitor.ps1
```

Parameters:

```powershell
# Check a specific tenant
.\Get-CAEnforcementReport.ps1 -TenantId "contoso.onmicrosoft.com"

# Monitor the last 14 days instead of the default 7
.\Get-CAEnforcementMonitor.ps1 -DaysBack 14

# Monitor from a specific date
.\Get-CAEnforcementMonitor.ps1 -Since "2026-05-13"

# Override the enforcement date (default: 2026-05-13)
.\Get-CAEnforcementReport.ps1 -EnforcementDate "2026-06-01"
.\Get-CAEnforcementMonitor.ps1 -EnforcementDate "2026-06-01"
```

All scripts use delegated permissions and prompt for interactive sign-in. No application credentials or stored secrets are required.

## Permissions

Each script lists its required Graph permissions in the `.NOTES` section of the script header. Required permissions across current scripts:

- `Policy.Read.All`
- `AuditLog.Read.All`
- `Application.Read.All`
