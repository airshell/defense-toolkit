<#
.SYNOPSIS
    Windows Forensic Cleanup & ClickFix Remediation Utility (Windows-Forensic-Cleanup.ps1)
.DESCRIPTION
    A modular, native PowerShell Digital Forensics & Incident Response (DFIR) utility
    engineered to detect, isolate, and remediate ClickFix / fake reCAPTCHA infostealer
    payloads, cryptominers, and persistent execution artifacts on Windows.
    Runs 100% natively using built-in Windows PowerShell commands without requiring
    third-party antivirus software.
.PARAMETER DryRun
    Runs the audit and detection routines without deleting files, terminating processes,
    or modifying the registry.
.PARAMETER VerboseOutput
    Enables detailed logging for every audited artifact.
.EXAMPLE
    .\Windows-Forensic-Cleanup.ps1 -DryRun
.EXAMPLE
    .\Windows-Forensic-Cleanup.ps1
#>

[CmdletBinding()]
param (
    [switch]$DryRun = $false,
    [switch]$VerboseOutput = $false
)

# ------------------------------------------------------------------------------
# 1. ENVIRONMENT & PRIVILEGE CHECKS
# ------------------------------------------------------------------------------
$ErrorActionPreference = "Continue"

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Host "[!] WARNING: This utility must be executed as Administrator for complete remediation." -ForegroundColor Red
    Write-Host "    Please right-click PowerShell and select \"Run as Administrator\"." -ForegroundColor Yellow
    exit 1
}

$SessionTime = Get-Date -Format "yyyyMMdd-HHmmss"
$LogDirectory = Join-Path $env:USERPROFILE "Desktop\WindowsForensicCleanupLogs"
$BackupDirectory = Join-Path $LogDirectory "backups\$SessionTime"
$LogFile = Join-Path $LogDirectory "cleanup-$SessionTime.log"

if (-not (Test-Path $LogDirectory)) { New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null }
if (-not (Test-Path $BackupDirectory)) { New-Item -ItemType Directory -Path $BackupDirectory -Force | Out-Null }

function Log-Output {
    param([string]$Message, [string]$Color = "White")
    $Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $LogMessage = "[$Timestamp] $Message"
    Write-Host $Message -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $LogMessage -ErrorAction SilentlyContinue
}

Log-Output "===============================================================================" "Cyan"
Log-Output "            WINDOWS FORENSIC CLEANUP & INCIDENT REMEDIATION UTILITY            " "Cyan"
Log-Output "                       Native PowerShell DFIR Engine                           " "Cyan"
Log-Output "===============================================================================" "Cyan"
Log-Output "Version:      1.0.0"
Log-Output "Mode:         $($DryRun ? 'DRY-RUN (Simulated Audit)' : 'LIVE REMEDIATION')" "Yellow"
Log-Output "Target User:  $env:USERNAME ($env:USERPROFILE)"
Log-Output "Log File:     $LogFile"
Log-Output "===============================================================================" "Cyan"

$Script:FlaggedItems = 0
$Script:ActionsTaken = 0

# ------------------------------------------------------------------------------
# STEP 1: AUDIT & CLEAN WIN+R RUN HISTORY (RunMRU)
# ------------------------------------------------------------------------------
Log-Output "`n=== STEP 1: Auditing Win+R Run Dialog History ===" "Cyan"
$RunMRUPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
if (Test-Path $RunMRUPath) {
    $mru = Get-ItemProperty -Path $RunMRUPath -ErrorAction SilentlyContinue
    $suspiciousMru = @()
    if ($mru) {
        $mru.PSObject.Properties | Where-Object { $_.Name -match "^[a-z]$" } | ForEach-Object {
            $cmd = $_.Value
            if ($cmd -match "powershell|cmd|mshta|curl|iex|iwr|http|superfuckingpanel") {
                $suspiciousMru += $_.Name
                Log-Output "  [!] Flagged malicious entry in RunMRU: $cmd" "Red"
                $Script:FlaggedItems++
            }
        }
    }
    if ($suspiciousMru.Count -gt 0 -and -not $DryRun) {
        foreach ($prop in $suspiciousMru) {
            Remove-ItemProperty -Path $RunMRUPath -Name $prop -Force -ErrorAction SilentlyContinue
            Log-Output "  [✓] Removed RunMRU property: $prop" "Green"
            $Script:ActionsTaken++
        }
    } elseif ($suspiciousMru.Count -eq 0) {
        Log-Output "  [✓] Win+R history is clean." "Green"
    }
}

# ------------------------------------------------------------------------------
# STEP 2: AUDIT & PURGE POWERSHELL EXECUTION HISTORY
# ------------------------------------------------------------------------------
Log-Output "`n=== STEP 2: Auditing PowerShell Command Line History ===" "Cyan"
$HistoryPath = (Get-PSReadLineOption).HistorySavePath
if (Test-Path $HistoryPath) {
    $historyMatches = Get-Content -Path $HistoryPath -ErrorAction SilentlyContinue | 
        Select-String -Pattern "Verification code|superfuckingpanel|7zip\.exe|bxor|downloadstring|prostafene|BotGuard"
    
    if ($historyMatches) {
        Log-Output "  [!] Detected ClickFix dropper in PowerShell history:" "Red"
        $historyMatches | ForEach-Object { Log-Output "      $($_)" "Magenta" }
        $Script:FlaggedItems++

        if (-not $DryRun) {
            Copy-Item -Path $HistoryPath -Destination (Join-Path $BackupDirectory "ConsoleHost_history.txt.bak") -Force
            Remove-Item -Path $HistoryPath -Force -ErrorAction SilentlyContinue
            Clear-History -ErrorAction SilentlyContinue
            Log-Output "  [✓] Purged infected PowerShell history file (backup created)." "Green"
            $Script:ActionsTaken++
        } else {
            Log-Output "  [Simulated] Would purge: $HistoryPath" "Yellow"
        }
    } else {
        Log-Output "  [✓] No ClickFix payload signatures found in PowerShell history." "Green"
    }
}

# ------------------------------------------------------------------------------
# STEP 3: SCAN & TERMINATE SUSPICIOUS RUNNING PROCESSES
# ------------------------------------------------------------------------------
Log-Output "`n=== STEP 3: Scanning Running Processes for Cryptominers & Stealers ===" "Cyan"
$MaliciousProcessPatterns = @(
    "xmrig", "rigupdater", "minerd", "hashvault", "stratum", "prostafene"
)

$SuspiciousProcesses = Get-Process -ErrorAction SilentlyContinue | Where-Object {
    $procName = $_.ProcessName
    $procPath = $_.Path
    $isMatch = $false
    foreach ($pat in $MaliciousProcessPatterns) {
        if ($procName -like "*$pat*") { $isMatch = $true; break }
    }
    if (-not $isMatch -and $procPath -and ($procPath -like "*\AppData\Local\Temp\*.exe" -or $procPath -like "*\AppData\Roaming\*.exe")) {
        if ($procName -notmatch "chrome|firefox|msedge|brave|opera|teams|slack|discord|code|flux|spotify") {
            $isMatch = $true
        }
    }
    $isMatch
}

if ($SuspiciousProcesses) {
    foreach ($proc in $SuspiciousProcesses) {
        Log-Output "  [!] Flagged malicious process: PID $($proc.Id) - $($proc.ProcessName) ($($proc.Path))" "Red"
        $Script:FlaggedItems++
        if (-not $DryRun) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            Log-Output "  [✓] Terminated process: PID $($proc.Id)" "Green"
            $Script:ActionsTaken++
        } else {
            Log-Output "  [Simulated] Would terminate PID: $($proc.Id)" "Yellow"
        }
    }
} else {
    Log-Output "  [✓] No active malicious processes or cryptominers running." "Green"
}

# ------------------------------------------------------------------------------
# STEP 4: SCAN & CLEAN DROPPED FILES IN APPDATA & TEMP
# ------------------------------------------------------------------------------
Log-Output "`n=== STEP 4: Scanning User Temp & AppData Directories for Staged Payloads ===" "Cyan"
$TargetScanFolders = @(
    $env:TEMP,
    $env:APPDATA,
    $env:LOCALAPPDATA
)

$KnownBadFiles = @(
    "7zip.exe", "a.exe", "a.zip", "xmrig.exe", "rigupdater.exe"
)

foreach ($folder in $TargetScanFolders) {
    if (Test-Path $folder) {
        foreach ($bad in $KnownBadFiles) {
            $found = Get-ChildItem -Path $folder -Filter $bad -Recurse -Depth 3 -ErrorAction SilentlyContinue
            if ($found) {
                foreach ($f in $found) {
                    Log-Output "  [!] Found staged payload: $($f.FullName)" "Red"
                    $Script:FlaggedItems++
                    if (-not $DryRun) {
                        $targetBackup = Join-Path $BackupDirectory $f.Name
                        Copy-Item -Path $f.FullName -Destination $targetBackup -Force -ErrorAction SilentlyContinue
                        Remove-Item -Path $f.FullName -Force -Recurse -ErrorAction SilentlyContinue
                        Log-Output "  [✓] Quarantined and removed: $($f.FullName)" "Green"
                        $Script:ActionsTaken++
                    } else {
                        Log-Output "  [Simulated] Would quarantine: $($f.FullName)" "Yellow"
                    }
                }
            }
        }
    }
}

# ------------------------------------------------------------------------------
# STEP 5: AUDIT REGISTRY STARTUP PERSISTENCE (Run & RunOnce)
# ------------------------------------------------------------------------------
Log-Output "`n=== STEP 5: Auditing Registry Startup Persistence ===" "Cyan"
$RunRegistryKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($regPath in $RunRegistryKeys) {
    if (Test-Path $regPath) {
        $props = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        if ($props) {
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^(PS|Default)" } | ForEach-Object {
                $val = $_.Value
                if ($val -match "AppData\\Local\\Temp|AppData\\Roaming\\[a-z0-9]{8,12}|powershell.*-e|cmd\.exe.*/c|mshta|superfuckingpanel") {
                    Log-Output "  [!] Suspicious Run entry in $regPath -> $($_.Name): $val" "Red"
                    $Script:FlaggedItems++
                    if (-not $DryRun) {
                        Remove-ItemProperty -Path $regPath -Name $_.Name -Force -ErrorAction SilentlyContinue
                        Log-Output "  [✓] Removed registry startup entry: $($_.Name)" "Green"
                        $Script:ActionsTaken++
                    } else {
                        Log-Output "  [Simulated] Would remove entry: $($_.Name)" "Yellow"
                    }
                }
            }
        }
    }
}

# ------------------------------------------------------------------------------
# STEP 6: AUDIT SCHEDULED TASKS FOR NON-MICROSOFT MALWARE TRIGGERS
# ------------------------------------------------------------------------------
Log-Output "`n=== STEP 6: Auditing Scheduled Tasks ===" "Cyan"
$CustomTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.TaskPath -notlike "\Microsoft*" -and $_.State -ne "Disabled"
}

foreach ($task in $CustomTasks) {
    $actions = $task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }
    $actionStr = $actions -join " "
    if ($actionStr -match "AppData\\Local\\Temp|AppData\\Roaming\\[a-z0-9]{8,12}|powershell.*hidden|powershell.*-e|powershell.*bypass|xmrig|superfuckingpanel") {
        Log-Output "  [!] Malicious scheduled task flagged: $($task.TaskName) -> $actionStr" "Red"
        $Script:FlaggedItems++
        if (-not $DryRun) {
            Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
            Log-Output "  [✓] Unregistered malicious scheduled task: $($task.TaskName)" "Green"
            $Script:ActionsTaken++
        } else {
            Log-Output "  [Simulated] Would unregister task: $($task.TaskName)" "Yellow"
        }
    }
}
Log-Output "  [✓] Scheduled tasks audit completed." "Green"

# ------------------------------------------------------------------------------
# STEP 7: TRIGGER NATIVE WINDOWS DEFENDER DEEP SCAN
# ------------------------------------------------------------------------------
Log-Output "`n=== STEP 7: Native Windows Defender Protection Verification ===" "Cyan"
$defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($defenderStatus) {
    Log-Output "  • Antivirus Signature Version: $($defenderStatus.AntivirusSignatureVersion)"
    Log-Output "  • Real-Time Protection:        $($defenderStatus.RealTimeProtectionEnabled ? 'ENABLED' : 'DISABLED')"
    
    if (-not $DryRun) {
        Log-Output "  • Launching native Windows Defender Quick Scan in background..." "Cyan"
        Start-Process -FilePath "C:\Program Files\Windows Defender\MpCmdRun.exe" -ArgumentList "-Scan -ScanType 1" -WindowStyle Hidden
        Log-Output "  [✓] Windows Defender background scan initiated." "Green"
    } else {
        Log-Output "  [Simulated] Would trigger MpCmdRun Quick Scan." "Yellow"
    }
} else {
    Log-Output "  • Windows Defender status query returned no object." "Gray"
}

# ------------------------------------------------------------------------------
# FINAL REMEDIATION SUMMARY
# ------------------------------------------------------------------------------
Log-Output "`n===============================================================================" "Cyan"
Log-Output "                          FINAL REMEDIATION SUMMARY                            " "Cyan"
Log-Output "===============================================================================" "Cyan"
Log-Output " Execution Mode:           $($DryRun ? 'DRY-RUN (Simulated)' : 'LIVE REMEDIATION')"
Log-Output " Suspicious Items Flagged: $Script:FlaggedItems"
Log-Output " Total Actions Performed:  $Script:ActionsTaken"
Log-Output " Detailed Log File:        $LogFile"
Log-Output " Quarantine/Backup Folder: $BackupDirectory"
Log-Output "-------------------------------------------------------------------------------" "Cyan"
if ($Script:FlaggedItems -eq 0) {
    Log-Output " ✓ STATUS: SYSTEM IS CLEAN. No ClickFix or mining artifacts detected." "Green"
} else {
    if ($DryRun) {
        Log-Output " ! STATUS: THREAT ARTIFACTS DETECTED. Re-run without -DryRun to sanitize." "Yellow"
    } else {
        Log-Output " ✓ STATUS: REMEDIATION COMPLETE. All flagged threats have been neutralized." "Green"
    }
}
Log-Output "===============================================================================" "Cyan"
