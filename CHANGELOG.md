# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-11-09

### Fixed
- **LocalAdmin-Hygiene:** Removed the `^AzureAD\\` allowlist pattern, which approved every Entra ID user as a local administrator. Entra ID role SIDs are now added explicitly.
- **LocalAdmin-Hygiene:** Added an ADSI fallback for error 1789 when the group contains orphaned or unresolvable SIDs.
- **BitLocker-Escrow:** Detection now requires an escrow confirmation (Event ID 845) for the RecoveryPassword protector instead of only checking that the protector exists.
- **BitLocker-Escrow:** An initial encryption still in progress is reported as `PENDING` instead of non-compliant.
- **SystemHealth-VSS-Patching:** `vssadmin` parsing no longer depends on English labels; failed writers are now detected on Spanish and other non-English Windows builds.
- **Inventory tool:** Replaced a WMI repository check that was always reported as healthy with a real Winmgmt service check.

### Changed
- **LocalAdmin-Hygiene:** The remediation is report-only by default (`$Enforce = $false`) and reports partial failures per account.
- **BitLocker-Escrow:** The remediation no longer enables BitLocker on decrypted drives; initial encryption belongs to the Intune disk encryption policy.
- Moved `Invoke-EndpointSupportAndInventory.ps1` to `tools/` because it is not a detection/remediation pair.
- Remediation messages now describe exactly what was changed, including `WHATIF` output.

### Added
- GitHub Actions CI: PSScriptAnalyzer and Pester on Windows PowerShell 5.1 and PowerShell 7.
- Tests for escrow confirmation, pending encryption, Entra ID users, and Spanish `vssadmin` output.

## [1.0.0] - 2026-10-23

### Added
- **BitLocker-Escrow (`Detect-BitLockerEscrow.ps1` / `Remediate-BitLockerEscrow.ps1`):** Audits OS volume encryption state, resumes suspended BitLocker protection, creates missing 48-digit `RecoveryPassword` protectors, and escrows recovery keys to Microsoft Entra ID.
- **LocalAdmin-Hygiene (`Detect-UnauthorizedLocalAdmins.ps1` / `Remediate-UnauthorizedLocalAdmins.ps1`):** Audits local `Administrators` (`S-1-5-32-544`) membership against an approved enterprise allowlist and removes unauthorized accounts while protecting the built-in RID `-500` account.
- **SystemHealth-VSS-Patching (`Detect-SystemBackupAndPatchHealth.ps1` / `Remediate-SystemBackupAndPatchHealth.ps1`):** Pre-backup and patch window checklist auditing Volume Shadow Copy (`vssadmin`) writer stability, `wuauserv`/`BITS`/`CryptSvc` service readiness, and system drive free space thresholds.
- Offline Pester 5 unit test suite (`tests/IntuneRemediations.Tests.ps1`) validating exit code semantics (`0` vs `1`) across all three remediation packages.
