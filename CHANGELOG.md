# Changelog

All notable changes to the **macOS Forensic Cleanup Utility** (`macOS-Forensic-Cleanup.sh`) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2026-09-17

### Added
- **ClickFix / Polygon Dead-Drop C2 & Mining IOC Enhancements**:
  - Added mining pool detection for `hashvault` / `pool.hashvault.pro` (including TLS port 443 connections).
  - Added secondary C2 staging domain pattern `jse8x92s.me` and smart contract target `0xA3a603F8a454a9c905b4c579Bb72628F7C15C2A0`.
  - Added process arguments detection for `txid=` and `bmodule` payloads.
  - Added explicit regex detection for `base64 -d | osascript` pipelines in LaunchAgents.
- **Infostealer & Exfiltration Staging Cleanup**:
  - Expanded `KNOWN_MALWARE_PATHS` to clean up infostealer upload logs (`/private/tmp/updstat.txt`), exfiltration zip archives (`/private/tmp/*.zip`), and temporary credential staging directories.
- **Forensic Hash Audit Trail**:
  - Enhanced `backup_file()` to compute and log SHA-256 cryptographic hashes for all remediated files before archiving and deletion.
- **Expanded Network Socket Auditing**:
  - Added process-level connection auditing in Step 14 (`lsof -i -P -n`) to flag outbound connections initiated by malware processes regardless of destination port (catching TLS 443 connections).
- **Cross-Platform Threat Documentation**:
  - Published [`CLOUDFLARE_WORKER_THREAT_ADVISORY.md`](CLOUDFLARE_WORKER_THREAT_ADVISORY.md) detailing edge-level worker injections, supply-chain risks, and blockchain C2 resolution (`eth_call` 0x6d4ce63c).
  - Published [`WINDOWS_CLICKFIX_REMEDIATION_GUIDE.md`](WINDOWS_CLICKFIX_REMEDIATION_GUIDE.md) providing step-by-step PowerShell detection and remediation procedures for non-technical users exposed to fake reCAPTCHA prompts.

## [1.0.0] - 2026-08-07

### Added
- **16-Step Modular Remediation Engine**:
  - System metadata extraction (macOS version, build, architecture, SIP, Gatekeeper, XProtect, MRT).
  - Malicious process discovery and termination (`xmrig`, `rigupdater`, RPC droppers).
  - Automated deletion of known temporary malware paths (`/private/tmp/rigupdater`, `/tmp/xmrig*`, `~/.xmrig.json`).
  - LaunchAgent & LaunchDaemon auditing and remediation with Apple system directory read-only guardrails.
  - Login item audit using AppleScript (`osascript`).
  - User and system `cron` job schedule inspection.
  - Shell profile persistence scanner (`.zshrc`, `.zprofile`, `.bash_profile`, `.bashrc`).
  - Malware IOC string search targeting Polygon RPC gateways (`polygon.drpc.org`, `tenderly.rpc`) and base64 AppleScript runners.
  - Code signature verification (`codesign`, `spctl`) for unsigned Mach-O binaries in `/tmp` and caches.
  - Extended attribute quarantine inspection (`com.apple.quarantine`).
  - Application Support hidden directory and executable script audit.
  - Cache folder executable audit (`~/Library/Caches`).
  - Read-only SSH key and configuration audit (`~/.ssh/authorized_keys`).
  - Network connection and listening socket inspection (`lsof`, `netstat`).
  - Post-cleanup verification sweep.
  - ANSI terminal summary output and complete log reporting.
- **CLI Options**:
  - `--dry-run` (`-d`): Simulated audit mode.
  - `--verbose` (`-v`): Granular debug output.
  - `--quiet` (`-q`): Suppressed stdout output for headless/scripted invocation.
  - `--log-file FILE` (`-l`): Custom log destination.
  - `--version` (`-V`): Version reporting.
  - `--help` (`-h`): Help menu and usage examples.
- **Defensive Infrastructure**:
  - `set -Eeuo pipefail` strict execution configuration.
  - `ERR`, `EXIT`, `INT`, `TERM` signal error trapping.
  - Automated timestamped file backups in `~/Desktop/ForensicCleanupLogs/backups/`.
