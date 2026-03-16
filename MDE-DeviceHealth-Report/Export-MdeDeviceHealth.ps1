#Requires -Version 5.1
<#
.SYNOPSIS
    MDE Device Health Export Tool v2.1
    Exports device inventory and AV health status from Microsoft Defender for Endpoint

.DESCRIPTION
    This script exports:
    - Device Inventory (Machines API): id, computerDnsName, firstSeen, lastSeen, osPlatform, version, osBuild, healthStatus, machineTags
    - AV Health Status (Advanced Hunting): All 18 fields including engine/signature/platform versions and scan results

.AUTHOR
    Michael Crane - Microsoft CSA

.NOTES
    Required API Permissions (WindowsDefenderATP):
    - Machine.Read.All
    - AdvancedQuery.Read.All
#>

[CmdletBinding()]
param (
    [ValidateSet("Commercial", "GCC", "GCCHigh", "")]
    [string]$EnvironmentOverride,
    [string]$OutputFolder
)

#region ==================== CONFIGURATION - EDIT THESE VALUES ====================
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  EDIT THE VALUES BELOW BEFORE RUNNING                                         ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# Your Entra App Registration Details
$tenantId     = ""       # <-- Your Tenant ID
$clientId     = ""       # <-- Your App (Client) ID  
$clientSecret = ""       # <-- Your Client Secret

# Environment: "Commercial", "GCC", or "GCCHigh"
# Leave blank to auto-detect based on your tenant
$Environment = ""

#endregion ==================== END CONFIGURATION ====================

# Override environment if passed as parameter
if ($EnvironmentOverride) { $Environment = $EnvironmentOverride }

# Environment endpoints
$envConfig = @{
    Commercial = @{ 
        LoginUri = "https://login.microsoftonline.com"
        BaseUri  = "https://api.securitycenter.microsoft.com" 
    }
    GCC = @{ 
        LoginUri = "https://login.microsoftonline.com"
        BaseUri  = "https://api-gcc.securitycenter.microsoft.us" 
    }
    GCCHigh = @{ 
        LoginUri = "https://login.microsoftonline.us"
        BaseUri  = "https://api-gov.securitycenter.microsoft.us" 
    }
}

# Functions
function Get-MdeToken {
    param ($TenantId, $ClientId, $ClientSecret, $LoginUri, $ResourceUri)
    $body = @{ 
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
        resource      = $ResourceUri 
    }
    $response = Invoke-RestMethod -Uri "$LoginUri/$TenantId/oauth2/token" -Method POST -Body $body -ContentType "application/x-www-form-urlencoded"
    return $response.access_token
}

function Invoke-MdeApi {
    param ([string]$Uri, [string]$Token, [string]$Method = "GET", [object]$Body = $null)
    $headers = @{ Authorization = "Bearer $Token"; "Content-Type" = "application/json" }
    if ($Body) {
        return Invoke-RestMethod -Uri $Uri -Headers $headers -Method $Method -Body ($Body | ConvertTo-Json -Depth 10)
    } else {
        return Invoke-RestMethod -Uri $Uri -Headers $headers -Method $Method
    }
}

function Detect-Environment {
    param ($TenantId, $ClientId, $ClientSecret)
    
    $tryOrder = @("GCC", "Commercial", "GCCHigh")
    
    foreach ($env in $tryOrder) {
        $settings = $script:envConfig[$env]
        try {
            Write-Host "        Testing $env..." -ForegroundColor DarkGray -NoNewline
            $body = @{ 
                grant_type    = "client_credentials"
                client_id     = $ClientId
                client_secret = $ClientSecret
                resource      = $settings.BaseUri 
            }
            $null = Invoke-RestMethod -Uri "$($settings.LoginUri)/$TenantId/oauth2/token" -Method POST -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
            Write-Host " OK" -ForegroundColor Green
            return $env
        } catch {
            Write-Host " No" -ForegroundColor DarkGray
            continue
        }
    }
    return $null
}

# Main Script
Clear-Host
Write-Host ""
Write-Host "  +================================================================+" -ForegroundColor Cyan
Write-Host "  |       MDE Device Health Export Tool v2.1                       |" -ForegroundColor Cyan
Write-Host "  |       Microsoft Defender for Endpoint                          |" -ForegroundColor Cyan
Write-Host "  +================================================================+" -ForegroundColor Cyan
Write-Host ""

# Validate configuration
if (-not $tenantId -or $tenantId -eq "YOUR-TENANT-ID-HERE") {
    Write-Host "  [ERROR] Please configure your Tenant ID in the script!" -ForegroundColor Red
    Write-Host "          Open this script and edit the CONFIGURATION section." -ForegroundColor Yellow
    exit 1
}
if (-not $clientId -or $clientId -eq "YOUR-CLIENT-ID-HERE") {
    Write-Host "  [ERROR] Please configure your Client ID in the script!" -ForegroundColor Red
    exit 1
}
if (-not $clientSecret -or $clientSecret -eq "YOUR-CLIENT-SECRET-HERE") {
    Write-Host "  [ERROR] Please configure your Client Secret in the script!" -ForegroundColor Red
    exit 1
}

# Set output folder
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $OutputFolder) { $OutputFolder = Join-Path $scriptPath "Output" }
if (!(Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"

# Auto-detect or validate environment
Write-Host "  [1/4] Detecting environment..." -ForegroundColor Yellow
if (-not $Environment) {
    $Environment = Detect-Environment -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret
    if (-not $Environment) {
        Write-Host "        [FAIL] Could not auto-detect environment." -ForegroundColor Red
        Write-Host "        Please set Environment variable in the script." -ForegroundColor Yellow
        exit 1
    }
    Write-Host "        [OK] Auto-detected: $Environment" -ForegroundColor Green
} else {
    Write-Host "        [OK] Using configured: $Environment" -ForegroundColor Green
}

$envSettings = $envConfig[$Environment]
Write-Host "        Login: $($envSettings.LoginUri)" -ForegroundColor DarkGray
Write-Host "        API:   $($envSettings.BaseUri)" -ForegroundColor DarkGray

# Get Token
Write-Host "  [2/4] Acquiring access token..." -ForegroundColor Yellow
try {
    $token = Get-MdeToken -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret -LoginUri $envSettings.LoginUri -ResourceUri $envSettings.BaseUri
    Write-Host "        [OK] Token acquired" -ForegroundColor Green
} catch {
    Write-Host "        [FAIL] $_" -ForegroundColor Red
    exit 1
}

# Get Devices from Machines API
Write-Host "  [3/4] Fetching device inventory..." -ForegroundColor Yellow
$devices = @()
try {
    $machinesResponse = Invoke-MdeApi -Uri "$($envSettings.BaseUri)/api/machines" -Token $token
    $devices = $machinesResponse.value
    Write-Host "        [OK] Found $($devices.Count) devices" -ForegroundColor Green
    
    $devicesCsv = $devices | Select-Object id, computerDnsName, firstSeen, lastSeen, osPlatform, version, osBuild, healthStatus, @{N='machineTags';E={($_.machineTags) -join '; '}}
    $devicesPath = Join-Path $OutputFolder "DeviceInfo_$timestamp.csv"
    $devicesCsv | Export-Csv -Path $devicesPath -NoTypeInformation
    Write-Host "        Saved: $devicesPath" -ForegroundColor DarkGray
} catch {
    Write-Host "        [FAIL] $_" -ForegroundColor Red
}

# Get AV Health + Extended Device Info via Advanced Hunting
Write-Host "  [4/4] Fetching AV health status + device info..." -ForegroundColor Yellow
$healthData = @()
try {
    $query = "let BootTimes = DeviceEvents | where Timestamp > ago(30d) | where InitiatingProcessId == 4 | summarize LastBootTime = max(InitiatingProcessCreationTime) by DeviceId; let DeviceDetails = DeviceInfo | where Timestamp > ago(30d) | summarize arg_max(Timestamp, *) by DeviceId | project DeviceId, Model, OSVersion, LoggedOnUsers, DeviceManualTags, DeviceDynamicTags; DeviceTvmInfoGathering | where Timestamp > ago(30d) | extend AF = parse_json(AdditionalFields) | extend AvScan = parse_json(tostring(AF.AvScanResults)) | extend _avMode = tostring(AF.AvMode), _avEngineVersion = tostring(AF.AvEngineVersion), _avEngineUpdateTime = tostring(AF.AvEngineUpdateTime), _avIsEngineUpToDate = coalesce(tostring(AF.AvIsEngineUpToDate), tostring(AF.AvIsEngineUptoDate), tostring(AF.AvIsEngineUptodate)), _avSignatureVersion = tostring(AF.AvSignatureVersion), _avSignatureUpdateTime = tostring(AF.AvSignatureUpdateTime), _avIsSignatureUpToDate = coalesce(tostring(AF.AvIsSignatureUpToDate), tostring(AF.AvIsSignatureUptoDate), tostring(AF.AvIsSignatureUptodate)), _avPlatformVersion = tostring(AF.AvPlatformVersion), _avPlatformUpdateTime = tostring(AF.AvPlatformUpdateTime), _avIsPlatformUpToDate = coalesce(tostring(AF.AvIsPlatformUpToDate), tostring(AF.AvIsPlatformUptoDate), tostring(AF.AvIsPlatformUptodate)), _quickScanTime = tostring(AvScan.Quick.Timestamp), _quickScanResult = tostring(AvScan.Quick.ScanStatus), _quickScanError = tostring(AvScan.Quick.ErrorCode), _fullScanTime = tostring(AvScan.Full.Timestamp), _fullScanResult = tostring(AvScan.Full.ScanStatus), _fullScanError = tostring(AvScan.Full.ErrorCode) | summarize arg_max(Timestamp, *) by DeviceId | join kind=leftouter DeviceDetails on DeviceId | join kind=leftouter BootTimes on DeviceId | project computerDnsName = DeviceName, model = Model, osVersion = OSVersion, loggedOnUsers = LoggedOnUsers, manualTags = DeviceManualTags, dynamicTags = DeviceDynamicTags, lastBootTime = LastBootTime, lastSeenTime = LastSeenTime, avMode = _avMode, avEngineVersion = _avEngineVersion, avEngineUpdateTime = _avEngineUpdateTime, avIsEngineUpToDate = _avIsEngineUpToDate, avSignatureVersion = _avSignatureVersion, avSignatureUpdateTime = _avSignatureUpdateTime, avIsSignatureUpToDate = _avIsSignatureUpToDate, avPlatformVersion = _avPlatformVersion, avPlatformUpdateTime = _avPlatformUpdateTime, avIsPlatformUpToDate = _avIsPlatformUpToDate, quickScanTime = _quickScanTime, quickScanResult = _quickScanResult, quickScanError = _quickScanError, fullScanTime = _fullScanTime, fullScanResult = _fullScanResult, fullScanError = _fullScanError"
    
    $huntingBody = @{ Query = $query }
    $healthResponse = Invoke-MdeApi -Uri "$($envSettings.BaseUri)/api/advancedqueries/run" -Token $token -Method "POST" -Body $huntingBody
    $healthData = $healthResponse.Results
    
    if ($healthData.Count -gt 0) {
        Write-Host "        [OK] Found $($healthData.Count) health records" -ForegroundColor Green
        $healthPath = Join-Path $OutputFolder "DeviceHealth_$timestamp.csv"
        $healthData | Export-Csv -Path $healthPath -NoTypeInformation
        Write-Host "        Saved: $healthPath" -ForegroundColor DarkGray
    } else {
        Write-Host "        [WARN] No health data returned" -ForegroundColor Yellow
    }
} catch {
    Write-Host "        [FAIL] $_" -ForegroundColor Red
}

# Generate HTML Report
Write-Host ""
Write-Host "  Generating HTML report..." -ForegroundColor Yellow

$totalDevices = $devices.Count
$activeDevices = ($devices | Where-Object { $_.healthStatus -eq "Active" }).Count
$inactiveDevices = $totalDevices - $activeDevices
$engineUpToDate = ($healthData | Where-Object { $_.avIsEngineUpToDate -eq "True" -or $_.avIsEngineUpToDate -eq "true" }).Count
$sigUpToDate = ($healthData | Where-Object { $_.avIsSignatureUpToDate -eq "True" -or $_.avIsSignatureUpToDate -eq "true" }).Count
$healthTotal = $healthData.Count
$avModeMap = @{ "0" = "Active"; "1" = "Passive"; "2" = "Disabled"; "3" = "Other"; "4" = "EDR Blocked"; "5" = "Passive Audit"; "" = "Unknown" }
$reportDate = Get-Date -Format "MMMM dd, yyyy HH:mm:ss"

$htmlStart = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MDE Device Health Report</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', -apple-system, sans-serif; background: linear-gradient(135deg, #0f0f1a 0%, #1a1a2e 50%, #16213e 100%); color: #e8e8e8; min-height: 100vh; padding: 30px; }
.container { max-width: 1600px; margin: 0 auto; }
.header { background: linear-gradient(135deg, #0078d4 0%, #106ebe 50%, #005a9e 100%); border-radius: 16px; padding: 40px; margin-bottom: 30px; box-shadow: 0 10px 40px rgba(0,120,212,0.3); }
.header h1 { font-size: 2.5em; font-weight: 600; margin-bottom: 8px; }
.header-subtitle { font-size: 1.1em; opacity: 0.9; margin-bottom: 20px; }
.header-meta { display: flex; gap: 30px; flex-wrap: wrap; font-size: 0.95em; opacity: 0.85; }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 20px; margin-bottom: 30px; }
.stat-card { background: linear-gradient(145deg, rgba(255,255,255,0.08), rgba(255,255,255,0.02)); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 25px; text-align: center; transition: all 0.3s ease; }
.stat-card:hover { transform: translateY(-5px); box-shadow: 0 10px 30px rgba(0,0,0,0.3); }
.stat-value { font-size: 2.8em; font-weight: 700; line-height: 1; margin-bottom: 8px; }
.stat-label { font-size: 0.8em; text-transform: uppercase; letter-spacing: 1px; opacity: 0.7; }
.stat-card.blue .stat-value { color: #0078d4; }
.stat-card.green .stat-value { color: #10b981; }
.stat-card.red .stat-value { color: #ef4444; }
.stat-card.purple .stat-value { color: #8b5cf6; }
.section { background: linear-gradient(145deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)); border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 30px; margin-bottom: 30px; }
.section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; padding-bottom: 20px; border-bottom: 2px solid rgba(0,120,212,0.3); }
.section h2 { font-size: 1.4em; font-weight: 600; }
.search-box { display: flex; align-items: center; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.15); border-radius: 10px; padding: 10px 15px; }
.search-box:focus-within { border-color: #0078d4; box-shadow: 0 0 0 3px rgba(0,120,212,0.2); }
.search-box input { background: transparent; border: none; color: #e8e8e8; font-size: 0.95em; width: 200px; outline: none; }
.search-box input::placeholder { color: rgba(255,255,255,0.4); }
.table-wrapper { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
th { background: rgba(0,120,212,0.25); padding: 14px 10px; text-align: left; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; white-space: nowrap; }
td { padding: 12px 10px; border-bottom: 1px solid rgba(255,255,255,0.05); }
tr:hover { background: rgba(255,255,255,0.03); }
.device-name { font-weight: 600; color: #60a5fa; }
.badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.75em; font-weight: 600; }
.badge-active { background: rgba(16,185,129,0.2); color: #10b981; }
.badge-inactive { background: rgba(239,68,68,0.2); color: #ef4444; }
.badge-true { background: rgba(16,185,129,0.2); color: #10b981; }
.badge-false { background: rgba(239,68,68,0.2); color: #ef4444; }
.badge-unknown { background: rgba(156,163,175,0.2); color: #9ca3af; }
.badge-passive { background: rgba(245,158,11,0.2); color: #f59e0b; }
.version { font-family: Consolas, Monaco, monospace; font-size: 0.9em; color: #a78bfa; }
.timestamp { font-size: 0.9em; color: #9ca3af; }
.footer { text-align: center; padding: 20px; opacity: 0.5; font-size: 0.85em; }
</style>
</head>
<body>
<div class="container">
'@

$htmlHeader = @"
<div class="header">
<h1>MDE Device Health Report</h1>
<div class="header-subtitle">Microsoft Defender for Endpoint - Device Inventory & AV Health Status</div>
<div class="header-meta">
<span>Generated: $reportDate</span>
<span>Environment: $Environment</span>
<span>Total Devices: $totalDevices</span>
</div>
</div>

<div class="stats-grid">
<div class="stat-card blue"><div class="stat-value">$totalDevices</div><div class="stat-label">Total Devices</div></div>
<div class="stat-card green"><div class="stat-value">$activeDevices</div><div class="stat-label">Active Sensors</div></div>
<div class="stat-card red"><div class="stat-value">$inactiveDevices</div><div class="stat-label">Inactive</div></div>
<div class="stat-card green"><div class="stat-value">$engineUpToDate</div><div class="stat-label">Engine OK</div></div>
<div class="stat-card green"><div class="stat-value">$sigUpToDate</div><div class="stat-label">Sigs Current</div></div>
<div class="stat-card purple"><div class="stat-value">$healthTotal</div><div class="stat-label">Health Records</div></div>
</div>
"@

$htmlDeviceTableStart = @'
<div class="section">
<div class="section-header">
<h2>Device Inventory (Machines API)</h2>
<div class="search-box"><input type="text" placeholder="Search..." onkeyup="filterTable('devTable', this.value)"></div>
</div>
<div class="table-wrapper">
<table id="devTable">
<thead><tr><th>Device Name</th><th>ID</th><th>OS Platform</th><th>Version</th><th>Build</th><th>Health</th><th>First Seen</th><th>Last Seen</th><th>Tags</th></tr></thead>
<tbody>
'@

$deviceRows = ""
foreach ($d in $devices) {
    $healthBadge = if ($d.healthStatus -eq "Active") { "badge-active" } else { "badge-inactive" }
    $firstSeen = if ($d.firstSeen) { try { ([datetime]$d.firstSeen).ToString("yyyy-MM-dd HH:mm") } catch { "-" } } else { "-" }
    $lastSeen = if ($d.lastSeen) { try { ([datetime]$d.lastSeen).ToString("yyyy-MM-dd HH:mm") } catch { "-" } } else { "-" }
    $tags = if ($d.machineTags) { ($d.machineTags) -join ", " } else { "-" }
    $shortId = if ($d.id.Length -gt 10) { $d.id.Substring(0,10) + "..." } else { $d.id }
    $deviceRows += "<tr><td class='device-name'>$($d.computerDnsName)</td><td><span class='version' title='$($d.id)'>$shortId</span></td><td>$($d.osPlatform)</td><td>$($d.version)</td><td>$($d.osBuild)</td><td><span class='badge $healthBadge'>$($d.healthStatus)</span></td><td class='timestamp'>$firstSeen</td><td class='timestamp'>$lastSeen</td><td>$tags</td></tr>`n"
}

$htmlDeviceTableEnd = '</tbody></table></div></div>'

$htmlHealthTableStart = @'
<div class="section">
<div class="section-header">
<h2>AV Health Status + Extended Device Info</h2>
<div class="search-box"><input type="text" placeholder="Search..." onkeyup="filterTable('healthTable', this.value)"></div>
</div>
<div class="table-wrapper">
<table id="healthTable">
<thead><tr><th>Device</th><th>Model</th><th>OS Ver</th><th>Last User</th><th>Last Boot</th><th>Tags</th><th>AV Mode</th><th>Engine Ver</th><th>Eng OK</th><th>Sig Ver</th><th>Sig OK</th><th>Platform Ver</th><th>Plat OK</th><th>Quick Scan</th><th>Full Scan</th></tr></thead>
<tbody>
'@

$healthRows = ""
foreach ($h in $healthData) {
    $avModeName = $avModeMap[$h.avMode]
    if (-not $avModeName) { $avModeName = "Unknown" }
    $avModeClass = switch ($h.avMode) { "0" { "badge-active" } "1" { "badge-passive" } "2" { "badge-inactive" } default { "badge-unknown" } }
    $engOk = if ($h.avIsEngineUpToDate -eq "True" -or $h.avIsEngineUpToDate -eq "true") { "badge-true" } else { "badge-false" }
    $sigOk = if ($h.avIsSignatureUpToDate -eq "True" -or $h.avIsSignatureUpToDate -eq "true") { "badge-true" } else { "badge-false" }
    $platOk = if ($h.avIsPlatformUpToDate -eq "True" -or $h.avIsPlatformUpToDate -eq "true") { "badge-true" } else { "badge-false" }
    $engOkText = if ($h.avIsEngineUpToDate) { $h.avIsEngineUpToDate } else { "-" }
    $sigOkText = if ($h.avIsSignatureUpToDate) { $h.avIsSignatureUpToDate } else { "-" }
    $platOkText = if ($h.avIsPlatformUpToDate) { $h.avIsPlatformUpToDate } else { "-" }
    $quickTime = if ($h.quickScanTime) { try { ([datetime]$h.quickScanTime).ToString("MM-dd HH:mm") } catch { "-" } } else { "-" }
    $fullTime = if ($h.fullScanTime) { try { ([datetime]$h.fullScanTime).ToString("MM-dd HH:mm") } catch { "-" } } else { "-" }
    # New fields
    $model = if ($h.model) { $h.model } else { "-" }
    $osVer = if ($h.osVersion) { $h.osVersion } else { "-" }
    $lastUser = if ($h.loggedOnUsers) { try { $parsed = $h.loggedOnUsers | ConvertFrom-Json; if ($parsed) { ($parsed | Select-Object -First 1).UserName } else { "-" } } catch { $h.loggedOnUsers.Substring(0, [Math]::Min(20, $h.loggedOnUsers.Length)) } } else { "-" }
    $bootTime = if ($h.lastBootTime) { try { ([datetime]$h.lastBootTime).ToString("yyyy-MM-dd HH:mm") } catch { "-" } } else { "-" }
    $allTags = @()
    if ($h.manualTags) { $allTags += $h.manualTags }
    if ($h.dynamicTags) { $allTags += $h.dynamicTags }
    $tags = if ($allTags.Count -gt 0) { $allTags -join ", " } else { "-" }
    $healthRows += "<tr><td class='device-name'>$($h.computerDnsName)</td><td>$model</td><td>$osVer</td><td>$lastUser</td><td class='timestamp'>$bootTime</td><td>$tags</td><td><span class='badge $avModeClass'>$avModeName</span></td><td><span class='version'>$($h.avEngineVersion)</span></td><td><span class='badge $engOk'>$engOkText</span></td><td><span class='version'>$($h.avSignatureVersion)</span></td><td><span class='badge $sigOk'>$sigOkText</span></td><td><span class='version'>$($h.avPlatformVersion)</span></td><td><span class='badge $platOk'>$platOkText</span></td><td class='timestamp'>$quickTime</td><td class='timestamp'>$fullTime</td></tr>`n"
}

$htmlEnd = @'
</tbody></table></div></div>
<div class="footer">Generated by MDE Device Health Export Tool v2.1 | Microsoft Defender for Endpoint</div>
</div>
<script>
function filterTable(tableId, searchText) {
    const table = document.getElementById(tableId);
    const rows = table.getElementsByTagName('tbody')[0].getElementsByTagName('tr');
    const search = searchText.toLowerCase();
    for (let row of rows) { row.style.display = row.textContent.toLowerCase().includes(search) ? '' : 'none'; }
}
</script>
</body></html>
'@

$fullHtml = $htmlStart + $htmlHeader + $htmlDeviceTableStart + $deviceRows + $htmlDeviceTableEnd + $htmlHealthTableStart + $healthRows + $htmlEnd

$htmlPath = Join-Path $OutputFolder "MDE-Report_$timestamp.html"
$fullHtml | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Host "        [OK] Report generated" -ForegroundColor Green

# Summary
Write-Host ""
Write-Host "  +================================================================+" -ForegroundColor Green
Write-Host "  |                    Export Complete!                            |" -ForegroundColor Green
Write-Host "  +================================================================+" -ForegroundColor Green
Write-Host ""
Write-Host "  Environment: $Environment" -ForegroundColor Cyan
Write-Host "  Output folder: $OutputFolder" -ForegroundColor White
Get-ChildItem $OutputFolder -Filter "*$timestamp*" | ForEach-Object { Write-Host "    - $($_.Name)" -ForegroundColor DarkGray }
Write-Host ""
Write-Host "  Opening report in browser..." -ForegroundColor Yellow
Start-Process $htmlPath
