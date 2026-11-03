# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-23

### Added
- **BitLocker-Escrow (`Detect-BitLockerEscrow.ps1` / `Remediate-BitLockerEscrow.ps1`):** Audits OS volume encryption state, resumes suspended BitLocker protection, creates missing 48-digit `RecoveryPassword` protectors, and escrows recovery keys to Microsoft Entra ID.
- **LocalAdmin-Hygiene (`Detect-UnauthorizedLocalAdmins.ps1` / `Remediate-UnauthorizedLocalAdmins.ps1`):** Audits local `Administrators` (`S-1-5-32-544`) membership against an approved enterprise allowlist and removes unauthorized accounts while protecting the built-in RID `-500` account.
- **SystemHealth-VSS-Patching (`Detect-SystemBackupAndPatchHealth.ps1` / `Remediate-SystemBackupAndPatchHealth.ps1`):** Pre-backup and patch window checklist auditing Volume Shadow Copy (`vssadmin`) writer stability, `wuauserv`/`BITS`/`CryptSvc` service readiness, and system drive free space thresholds.
- Offline Pester 5 unit test suite (`tests/IntuneRemediations.Tests.ps1`) validating exit code semantics (`0` vs `1`) across all three remediation packages.
