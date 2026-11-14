# Intune-Proactive-Remediations

PowerShell detection and remediation script pairs for **Microsoft Intune Remediations** across Windows 10, Windows 11, and Windows Server endpoints. The same scripts can run from RMM script policies (for example GoTo Resolve or Syncro).

[![PowerShell 5.1 / 7+](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](https://microsoft.com/PowerShell)
[![CI](https://github.com/Santiago-Agudelo-R/Intune-Proactive-Remediations/actions/workflows/ci.yml/badge.svg)](https://github.com/Santiago-Agudelo-R/Intune-Proactive-Remediations/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Overview

Microsoft Intune Remediations and centralized RMM policies allow endpoint and systems engineers to detect and fix compliance, backup, and security posture drift automatically before incidents escalate to the Service Desk.

Every script pair in this repository follows the same conventions:
- **Deterministic Exit Codes:** Detection scripts return `exit 0` (Compliant / Healthy) or `exit 1` (Non-Compliant / Trigger Remediation).
- **Single-Line `STDOUT` Telemetry:** Outputs a concise, structured summary string on the final line so Intune and RMM operational dashboards can parse pre- and post-remediation status cleanly.
- **Zero Hardcoded Tenant Data:** No tenant IDs, domain names, or credentials are embedded in scripts.
- **Offline Testability:** Script evaluation logic is modularized so functions can be unit-tested offline with **Pester 5** (Windows PowerShell 5.1 and PowerShell 7) in GitHub Actions.
- **Safe by Default:** Destructive actions are opt-in. `Remediate-UnauthorizedLocalAdmins.ps1` runs report-only until you set `$Enforce = $true`, and no script enables BitLocker on its own.
- **Language-Independent:** Checks rely on exit codes, SIDs, and numeric states instead of English console text, so they work on Spanish or other non-English Windows builds.

---

## Remediation Catalog

| Package | Detection Script | Remediation Script | Run Context | Target Issue |
| :--- | :--- | :--- | :--- | :--- |
| **BitLocker-Escrow** | `Detect-BitLockerEscrow.ps1` | `Remediate-BitLockerEscrow.ps1` | `SYSTEM` (64-bit) | Detects suspended protection, a missing `RecoveryPassword` protector, or a protector with no escrow confirmation (Event ID 845). Resumes protection and escrows the key to Entra ID. |
| **LocalAdmin-Hygiene** | `Detect-UnauthorizedLocalAdmins.ps1` | `Remediate-UnauthorizedLocalAdmins.ps1` | `SYSTEM` (64-bit) | Audits local `Administrators` (`S-1-5-32-544`) membership against an approved allowlist. Report-only by default; removes unauthorized accounts when enforcement is enabled. |
| **SystemHealth-VSS-Patching** | `Detect-SystemBackupAndPatchHealth.ps1` | `Remediate-SystemBackupAndPatchHealth.ps1` | `SYSTEM` (64-bit) | Pre-backup and patch window checklist: detects failed Volume Shadow Copy (VSS) writers, disabled Windows Update (`wuauserv`/`BITS`/`CryptSvc`) services, and system drive disk pressure. Re-enables and restarts those services. |

---

## LocalAdmin-Hygiene: Entra ID joined devices

On Entra ID joined devices, the **Global Administrator** and **Microsoft Entra Joined Device Local Administrator** roles are added to the local Administrators group as SIDs that start with `S-1-12-1-`. Every Entra ID user also has an `S-1-12-1-` SID, so the scripts never approve `AzureAD\*` or `S-1-12-1-*` as a whole.

Before enabling enforcement:
1. Add your tenant's two role SIDs to `$ApprovedPatterns` in **both** scripts (run `Get-LocalGroupMember -SID S-1-5-32-544` on a pilot device to see them).
2. Deploy in report-only mode and review the output in Intune (Devices > Scripts and remediations).
3. Set `$Enforce = $true` in the remediation script only after the report is clean.

---

## Sample Detection & Remediation Flow

Intune captures the final `STDOUT` line and the process exit code (`0` = compliant, `1` = trigger remediation):

```text
# 1. Pre-Remediation Detection (Detect-BitLockerEscrow.ps1 -> Exit Code 1)
NON-COMPLIANT: Volume C: is encrypted (XtsAes256), but no Event ID 845 escrow confirmation was found for protector {4B9D1E2A-...}.

# 2. Remediation Execution (Remediate-BitLockerEscrow.ps1 -> Exit Code 0)
REMEDIATED: Escrowed RecoveryPassword protector {4B9D1E2A-...} to Entra ID and verified Event ID 845.

# 3. Post-Remediation Detection (Detect-BitLockerEscrow.ps1 -> Exit Code 0)
COMPLIANT: Volume C: ProtectionStatus=On, EncryptionPercentage=100%, Protector={4B9D1E2A-...} verified in Event ID 845.
```

### Operational Considerations (`SystemHealth-VSS-Patching`)
`Remediate-SystemBackupAndPatchHealth.ps1` re-enables and restarts `VSS`, `swprv`, `wuauserv`, `bits`, and `cryptsvc` only after `Detect-SystemBackupAndPatchHealth.ps1` returns `exit 1`. Schedule this package prior to nightly backup or maintenance windows rather than during active VSS snapshot operations.

---

## Tools

| Script | Purpose |
| :--- | :--- |
| `tools/Invoke-EndpointSupportAndInventory.ps1` | Support diagnostics (uptime, WinRM/WMI service state, hung services) and a Snipe-IT-style hardware asset payload. Supports `-DemoMode`. Not a remediation pair. |

---

## Deployment Settings

| Setting | Recommended Configuration |
| :--- | :--- |
| **Run this script using the logged-on credentials** | `No` (`SYSTEM` context) |
| **Enforce script signature check** | `No` (or `Yes` when signed by internal PKI Code Signing CA) |
| **Run script in 64-bit PowerShell** | `Yes` (Required to prevent `Sysnative` registry/cmdlet redirection issues) |
| **Schedule** | Daily (Prior to nightly VSS backup and maintenance windows) |

---

## Testing

```powershell
Invoke-Pester -Path ./tests -Output Detailed
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
