# ═══════════════════════════════════════════════════════════════════
# SELF-HIDE: Force-hide the console window immediately on startup
# This MUST run before anything else to prevent a visible terminal.
# ═══════════════════════════════════════════════════════════════════
try {
    Add-Type -Name Win -Namespace Native -MemberDefinition '
        [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
        [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    ' -ErrorAction SilentlyContinue
    $consoleWindow = [Native.Win]::GetConsoleWindow()
    if ($consoleWindow -ne [IntPtr]::Zero) {
        [Native.Win]::ShowWindow($consoleWindow, 0) | Out-Null  # 0 = SW_HIDE
    }
} catch {}

<# 
  RMS Monitoring Agent — Client-Side Detection Script
  Runs silently on client PCs, checks for flagged activity every 30 seconds.
  Sends alerts to the RMS server when monitored processes or window titles are detected.
  Logs all activity to C:\RMS\monitor.log for diagnostics.

  CONFIGURATION: Set $RMS_SERVER to your RMS server's IP/port.
  DEPLOYMENT:    Register as a scheduled task (see bottom of file).
#>

# ═══════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════
$RMS_SERVER     = "http://192.168.29.168:8000"
$CHECK_INTERVAL = 30   # seconds between checks
$RULES_REFRESH  = 300  # seconds between fetching updated rules from server
$DEDUP_MINUTES  = 5    # don't re-report same detection within this window
$LOG_FILE       = "C:\RMS\monitor.log"
$LOG_MAX_BYTES  = 5MB  # rotate log when it exceeds this size

# ═══════════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════════
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "[$timestamp] $Message"
    try {
        # Log rotation: if file exceeds max size, rename to .old
        if (Test-Path $LOG_FILE) {
            $size = (Get-Item $LOG_FILE).Length
            if ($size -gt $LOG_MAX_BYTES) {
                Move-Item -Path $LOG_FILE -Destination "$LOG_FILE.old" -Force -ErrorAction SilentlyContinue
            }
        }
        Add-Content -Path $LOG_FILE -Value $logLine -ErrorAction SilentlyContinue
    } catch { }
}

# ═══════════════════════════════════════════════════════════════════
# DEFAULT RULES (overridden by server rules when available)
# ═══════════════════════════════════════════════════════════════════
$DefaultProcessBlacklist = @(
    "steam", "steamwebhelper", "EpicGamesLauncher", "Battle.net", "Origin",
    "GalaxyClient", "UbisoftConnect",
    "VALORANT", "VALORANT-Win64-Shipping", "csgo", "cs2",
    "GTA5", "FiveM", "Minecraft", "javaw",
    "FortniteClient-Win64-Shipping", "RocketLeague",
    "Roblox", "RobloxPlayerBeta", "RobloxPlayerLauncher",
    "LeagueOfLegends", "PUBG", "TslGame", "Overwatch", "Dota2",
    "r5apex", "Warframe", "destiny2", "Among Us"
)

$DefaultWindowKeywords = @(
    "friv", "poki", "miniclip", "y8.com", "crazygames", "coolmathgames",
    "krunker", "1v1.lol", "shellshock", "slither", "agar.io", "diep.io",
    "zombs.io", "surviv.io", "skribbl.io", "unblocked games",
    "armor games", "kongregate", "newgrounds", "addicting games"
)

# ═══════════════════════════════════════════════════════════════════
# STATE
# ═══════════════════════════════════════════════════════════════════
$ProcessBlacklist = $DefaultProcessBlacklist
$WindowKeywords   = $DefaultWindowKeywords
$LastReported     = @{}
$LastRulesRefresh = [datetime]::MinValue

# ═══════════════════════════════════════════════════════════════════
# GET LOCAL CLIENT INFO
# ═══════════════════════════════════════════════════════════════════
function Get-ClientIP {
    try {
        # Prefer physical adapters (Ethernet, Wi-Fi) over virtual (VMware, ZeroTier, VPN)
        $preferred = Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object {
                $_.IPAddress -ne "127.0.0.1" -and
                $_.InterfaceAlias -notmatch "Loopback" -and
                $_.InterfaceAlias -notmatch "VMware" -and
                $_.InterfaceAlias -notmatch "VirtualBox" -and
                $_.InterfaceAlias -notmatch "Hyper-V" -and
                $_.InterfaceAlias -notmatch "ZeroTier" -and
                $_.InterfaceAlias -notmatch "OpenVPN" -and
                $_.InterfaceAlias -notmatch "Tailscale" -and
                $_.IPAddress -notmatch "^169\.254\."  # skip APIPA
            } | Select-Object -First 1
        if ($preferred) { return $preferred.IPAddress }
        # Fallback: any non-loopback IPv4
        $fallback = (Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.InterfaceAlias -notmatch "Loopback" } |
            Select-Object -First 1).IPAddress
        return $fallback
    } catch {
        return "0.0.0.0"
    }
}

$ClientIP   = Get-ClientIP
$ClientHost = $env:COMPUTERNAME

# Log startup
Write-Log "============================================"
Write-Log "Monitor STARTED. PID=$PID, Session=$([System.Diagnostics.Process]::GetCurrentProcess().SessionId)"
Write-Log "RMS Server: $RMS_SERVER"
Write-Log "Detected client IP: $ClientIP"
Write-Log "Hostname: $ClientHost"
Write-Log "Check interval: ${CHECK_INTERVAL}s, Rules refresh: ${RULES_REFRESH}s, Dedup: ${DEDUP_MINUTES}m"
Write-Log "============================================"

# ═══════════════════════════════════════════════════════════════════
# FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

function Refresh-Rules {
    <# Fetch the latest rules from the RMS server #>
    try {
        $url = "$RMS_SERVER/api/alerts/rules/"
        Write-Log "Fetching rules from $url"
        $resp = Invoke-RestMethod -Uri $url -TimeoutSec 5 -ErrorAction Stop
        if ($resp.process_names -and $resp.process_names.Count -gt 0) {
            $script:ProcessBlacklist = $resp.process_names
        }
        if ($resp.window_keywords -and $resp.window_keywords.Count -gt 0) {
            $script:WindowKeywords = $resp.window_keywords
        }
        $script:LastRulesRefresh = Get-Date
        Write-Log "Rules refreshed: $($script:ProcessBlacklist.Count) processes, $($script:WindowKeywords.Count) keywords"
    } catch {
        Write-Log "Rules refresh FAILED: $_"
    }
}

function Should-Report {
    param([string]$Type, [string]$Name)
    $key = "$Type|$Name"
    if ($LastReported.ContainsKey($key)) {
        $elapsed = (Get-Date) - $LastReported[$key]
        if ($elapsed.TotalMinutes -lt $DEDUP_MINUTES) {
            Write-Log "Skipping duplicate: $key (last reported $([math]::Round($elapsed.TotalMinutes,1)) minutes ago)"
            return $false
        }
    }
    return $true
}

function Send-Alert {
    param(
        [string]$AlertType,
        [string]$DetectedName,
        [string[]]$ProcessList
    )
    if (-not (Should-Report -Type $AlertType -Name $DetectedName)) { return }

    Write-Log "Sending alert: type=$AlertType, name=$DetectedName, ip=$ClientIP"

    # Build a clean process list (just process name strings, no objects)
    $cleanProcs = @()
    if ($ProcessList) {
        $cleanProcs = @($ProcessList | ForEach-Object { $_.ToString() } | Select-Object -First 100)
    }

    $bodyObj = @{
        client_ip     = $ClientIP
        hostname      = $ClientHost
        alert_type    = $AlertType
        detected_name = $DetectedName
        process_list  = $cleanProcs
        timestamp     = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
    }
    $body = $bodyObj | ConvertTo-Json -Compress -Depth 3

    # Encode as UTF-8 bytes to prevent encoding issues
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)

    try {
        $response = Invoke-RestMethod -Uri "$RMS_SERVER/api/alerts/report/" `
                          -Method POST `
                          -ContentType "application/json; charset=utf-8" `
                          -Body $bodyBytes `
                          -TimeoutSec 5 `
                          -ErrorAction Stop

        $key = "$AlertType|$DetectedName"
        $script:LastReported[$key] = Get-Date
        Write-Log "Alert sent successfully: status=$($response.status), ok=$($response.ok)"
    } catch {
        Write-Log "Alert send FAILED: $_"
    }
}

function Check-Processes {
    <# Check running process names against the monitored list #>
    $procs = Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName -Unique
    Write-Log "Running processes: $($procs.Count) total. Checking against $($ProcessBlacklist.Count) rules."
    foreach ($p in $procs) {
        foreach ($bad in $ProcessBlacklist) {
            if ($p -ieq $bad) {
                Write-Log "MATCH: Process '$p' found in blacklist!"
                Send-Alert -AlertType "process" -DetectedName "$p.exe" -ProcessList $procs
            }
        }
    }
    return $procs
}

function Check-WindowTitles {
    param([string[]]$ProcessList)
    <# Check visible window titles for flagged keywords.
       IMPORTANT: Get-Process.MainWindowTitle is EMPTY when running as SYSTEM (Session 0).
       We must use Win32 EnumWindows + GetWindowText to read titles across sessions. #>

    $windows = @()

    try {
        # Define Win32 API types for enumerating windows
        Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public class WindowEnumerator {
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll")]
    public static extern int GetWindowTextLength(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    public static List<string> GetAllWindowTitles() {
        var titles = new List<string>();
        EnumWindows(delegate(IntPtr hWnd, IntPtr lParam) {
            if (IsWindowVisible(hWnd)) {
                int len = GetWindowTextLength(hWnd);
                if (len > 0) {
                    var sb = new StringBuilder(len + 1);
                    GetWindowText(hWnd, sb, sb.Capacity);
                    string title = sb.ToString();
                    if (!string.IsNullOrWhiteSpace(title)) {
                        titles.Add(title);
                    }
                }
            }
            return true;
        }, IntPtr.Zero);
        return titles;
    }
}
"@ -ErrorAction SilentlyContinue

        $titles = [WindowEnumerator]::GetAllWindowTitles()

        # Filter out the monitor's own windows and common system noise
        $ignoreTitles = @(
            'Program Manager',
            'Windows Shell Experience Host',
            'Windows Input Experience',
            'NVIDIA GeForce Overlay',
            'Settings',
            'Widgets'
        )
        $myPid = $PID
        $filteredTitles = @()
        foreach ($t in $titles) {
            # Skip known system/noise windows
            if ($ignoreTitles -contains $t) { continue }
            # Skip our own PowerShell console window
            if ($t -like '*powershell*' -or $t -like '*monitor.ps1*' -or $t -like '*WindowsPowerShell*') { continue }
            $filteredTitles += $t
        }

        Write-Log "Window titles found (EnumWindows): $($filteredTitles.Count) (filtered from $($titles.Count) total)"
        foreach ($t in $filteredTitles) {
            Write-Log "  Title: $t"
            $windows += [PSCustomObject]@{ MainWindowTitle = $t }
        }
    } catch {
        Write-Log "EnumWindows FAILED: $_. Falling back to Get-Process."
        # Fallback: try Get-Process (works if NOT running as SYSTEM)
        $fallbackWindows = Get-Process -ErrorAction SilentlyContinue |
            Where-Object { $_.MainWindowTitle -ne "" } |
            Select-Object MainWindowTitle
        $count = 0
        foreach ($fw in $fallbackWindows) {
            $count++
            Write-Log "  Title (fallback): $($fw.MainWindowTitle)"
            $windows += $fw
        }
        Write-Log "Window titles found (Get-Process fallback): $count"
    }

    # Domain suffixes to strip for fuzzy matching
    $domainSuffixes = @(".io", ".com", ".gg", ".lol", ".net", ".org", ".tv", ".co", ".fun")

    foreach ($w in $windows) {
        $title = $w.MainWindowTitle.ToLower()
        $matched = $false
        foreach ($kw in $WindowKeywords) {
            $kwLower = $kw.ToLower()

            # Check 1: Does the title contain the full keyword as-is?
            if ($title.Contains($kwLower)) {
                Write-Log "MATCH: Window title '$($w.MainWindowTitle)' matched keyword '$kw'!"
                Send-Alert -AlertType "window_title" -DetectedName $w.MainWindowTitle -ProcessList $ProcessList
                $matched = $true
                break
            }

            # Check 2: Strip domain suffix and try the base word
            # e.g. "skribbl.io" → try "skribbl", "agar.io" → try "agar"
            foreach ($suffix in $domainSuffixes) {
                if ($kwLower.EndsWith($suffix)) {
                    $base = $kwLower.Substring(0, $kwLower.Length - $suffix.Length)
                    # Only use stripped version if base is 4+ chars (avoid false positives)
                    if ($base.Length -ge 4 -and $title.Contains($base)) {
                        Write-Log "MATCH: Window title '$($w.MainWindowTitle)' matched keyword '$base' (stripped from '$kw')!"
                        Send-Alert -AlertType "window_title" -DetectedName $w.MainWindowTitle -ProcessList $ProcessList
                        $matched = $true
                        break
                    }
                }
            }
            if ($matched) { break }
        }
    }
}

# ═══════════════════════════════════════════════════════════════════
# HEARTBEAT REGISTRATION (every 24 hours)
# ═══════════════════════════════════════════════════════════════════
$REG_FLAG_FILE = "C:\RMS\last_registered.txt"
$REG_INTERVAL_HOURS = 24

function Send-HeartbeatRegistration {
    try {
        # Check if we need to register
        $needsReg = $true
        if (Test-Path $REG_FLAG_FILE) {
            $lastReg = Get-Content $REG_FLAG_FILE -ErrorAction SilentlyContinue
            if ($lastReg) {
                $lastRegTime = [datetime]::Parse($lastReg)
                $hoursSince = ((Get-Date) - $lastRegTime).TotalHours
                if ($hoursSince -lt $REG_INTERVAL_HOURS) {
                    $needsReg = $false
                }
            }
        }
        if (-not $needsReg) { return }

        Write-Log "Sending 24-hour heartbeat registration..."
        $ip = Get-ClientIP
        $mac = ""
        $adapter = Get-NetAdapter | Where-Object {
            (Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress -eq $ip
        } | Select-Object -First 1
        if ($adapter) { $mac = $adapter.MacAddress.Replace('-', ':') }

        $os = ((Get-CimInstance Win32_OperatingSystem).Caption -replace '^Microsoft ', '')
        $osVer = (Get-CimInstance Win32_OperatingSystem).Version
        $cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name.Trim()
        $ram = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
        $disk = [math]::Round((Get-CimInstance Win32_DiskDrive | Where-Object { $_.MediaType -like '*fixed*' } | Select-Object -First 1).Size / 1GB)

        $body = @{
            registration_token = "rms-default-token-change-me"
            hostname = $env:COMPUTERNAME
            ip_address = $ip
            mac_address = $mac
            os_name = $os
            os_version = $osVer
            ssh_port = 22
            ssh_username = $env:USERNAME
            glances_port = 61208
            vnc_port = 5900
            cpu = $cpu
            ram_gb = $ram
            disk_gb = $disk
            heartbeat = $true
        } | ConvertTo-Json -Depth 3

        $resp = Invoke-RestMethod -Uri "$RMS_SERVER/api/clients/register/" -Method POST -ContentType "application/json" -Body $body -TimeoutSec 10
        if ($resp.ok) {
            Write-Log "Heartbeat registration OK: status=$($resp.status), id=$($resp.client_id)"
            Set-Content -Path $REG_FLAG_FILE -Value (Get-Date -Format "o") -Force
        } else {
            Write-Log "Heartbeat registration failed: $($resp.error)"
        }
    } catch {
        Write-Log "Heartbeat registration error: $($_)"
    }
}

# ═══════════════════════════════════════════════════════════════════
# MAIN LOOP
# ═══════════════════════════════════════════════════════════════════

Write-Log "Initial rules refresh..."
Refresh-Rules

# Send heartbeat on startup
Send-HeartbeatRegistration

$cycleCount = 0
while ($true) {
    $cycleCount++
    $elapsed = (Get-Date) - $LastRulesRefresh
    if ($elapsed.TotalSeconds -ge $RULES_REFRESH) {
        Write-Log "Rules cache expired ($([math]::Round($elapsed.TotalSeconds))s). Refreshing..."
        Refresh-Rules
    }

    Write-Log "--- Check cycle #$cycleCount start ---"
    $procList = Check-Processes
    Check-WindowTitles -ProcessList $procList
    Write-Log "--- Check cycle #$cycleCount end. Sleeping ${CHECK_INTERVAL}s ---"

    # Check heartbeat periodically (every 100 cycles ~ every ~50 minutes)
    if ($cycleCount % 100 -eq 0) {
        Send-HeartbeatRegistration
    }

    Start-Sleep -Seconds $CHECK_INTERVAL
}
