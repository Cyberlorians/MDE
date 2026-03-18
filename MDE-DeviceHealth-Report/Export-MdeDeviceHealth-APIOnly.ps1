#Requires -Version 5.1
<#
.SYNOPSIS
    MDE Device Health Export - API Only Version
    Exports device sensor state and onboarding status from Microsoft Defender for Endpoint

.DESCRIPTION
    Uses only the Machines API (no Advanced Hunting) for maximum compatibility.
    Exports: DeviceName, SensorState, OnboardingStatus, OS, LastSeen

.AUTHOR
    Michael Crane - Microsoft CSA

.NOTES
    Required API Permission (WindowsDefenderATP):
    - Machine.Read.All
#>

[CmdletBinding()]
param (
    [ValidateSet("Commercial", "GCC", "GCCHigh", "")]
    [string]$EnvironmentOverride,
    [string]$OutputFolder
)

#region ==================== CONFIGURATION ====================
$tenantId     = "YOUR-TENANT-ID"
$clientId     = "YOUR-CLIENT-ID"
$clientSecret = "YOUR-CLIENT-SECRET"
$Environment  = "GCCHigh"
#endregion ==================== END CONFIGURATION ====================

if ($EnvironmentOverride) { $Environment = $EnvironmentOverride }

$envConfig = @{
    Commercial = @{ LoginUri = "https://login.microsoftonline.com"; BaseUri = "https://api.securitycenter.microsoft.com" }
    GCC        = @{ LoginUri = "https://login.microsoftonline.com"; BaseUri = "https://api-gcc.securitycenter.microsoft.us" }
    GCCHigh    = @{ LoginUri = "https://login.microsoftonline.us";  BaseUri = "https://api-gov.securitycenter.microsoft.us" }
}

function Get-MdeToken {
    param ($TenantId, $ClientId, $ClientSecret, $LoginUri, $ResourceUri)
    $body = @{ grant_type = "client_credentials"; client_id = $ClientId; client_secret = $ClientSecret; resource = $ResourceUri }
    $response = Invoke-RestMethod -Uri "$LoginUri/$TenantId/oauth2/token" -Method POST -Body $body -ContentType "application/x-www-form-urlencoded"
    return $response.access_token
}

function Invoke-MdeApi {
    param ([string]$Uri, [string]$Token, [int]$MaxRetries = 3)
    $headers = @{ Authorization = "Bearer $Token"; "Content-Type" = "application/json" }
    $attempt = 0
    while ($attempt -lt $MaxRetries) {
        try {
            return Invoke-RestMethod -Uri $Uri -Headers $headers -Method GET -TimeoutSec 120
        } catch {
            $attempt++
            if ($attempt -eq $MaxRetries) { throw $_ }
            Write-Host " (retry $attempt)" -ForegroundColor Yellow -NoNewline
            Start-Sleep -Seconds (2 * $attempt)
        }
    }
}

# Main
Clear-Host
Write-Host ""
Write-Host "  MDE Device Health Export (API Only)" -ForegroundColor Cyan
Write-Host "  ====================================" -ForegroundColor Cyan
Write-Host ""

# Validate config
if (-not $tenantId -or -not $clientId -or -not $clientSecret) {
    Write-Host "  [ERROR] Please configure credentials in the script!" -ForegroundColor Red
    exit 1
}

# Setup
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $OutputFolder) { $OutputFolder = Join-Path $scriptPath "Output" }
if (!(Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$envSettings = $envConfig[$Environment]

Write-Host "  [1/3] Acquiring token..." -ForegroundColor Yellow
try {
    $token = Get-MdeToken -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret -LoginUri $envSettings.LoginUri -ResourceUri $envSettings.BaseUri
    Write-Host "        OK - $Environment" -ForegroundColor Green
} catch {
    Write-Host "        FAILED: $_" -ForegroundColor Red
    exit 1
}

Write-Host "  [2/3] Fetching devices (with pagination)..." -ForegroundColor Yellow
$devices = @()
$uri = "$($envSettings.BaseUri)/api/machines?`$top=10000"
$pageCount = 0
do {
    $pageCount++
    Write-Host "        Page $pageCount..." -ForegroundColor DarkGray -NoNewline
    try {
        $response = Invoke-MdeApi -Uri $uri -Token $token
        if ($response.value) {
            $devices += $response.value
            Write-Host " +$($response.value.Count) (total: $($devices.Count))" -ForegroundColor DarkGray
        }
        $uri = $response.'@odata.nextLink'
    } catch {
        Write-Host " ERROR: $_" -ForegroundColor Red
        if ($pageCount -eq 1) { throw "Failed to fetch devices: $_" }
        break
    }
} while ($uri)
Write-Host "        OK - $($devices.Count) devices fetched" -ForegroundColor Green

Write-Host "  [3/3] Building report..." -ForegroundColor Yellow

# Build results
$results = foreach ($device in $devices) {
    # Build OS display - combine platform and version/build info
    $osDisplay = $device.osPlatform
    if ($device.osVersion) { $osDisplay = "$($device.osPlatform) $($device.osVersion)" }
    elseif ($device.osBuild) { $osDisplay = "$($device.osPlatform) ($($device.osBuild))" }
    
    [PSCustomObject]@{
        DeviceName       = if ($device.computerDnsName) { $device.computerDnsName } else { $device.id }
        SensorState      = if ($device.healthStatus) { $device.healthStatus } else { "Unknown" }
        OnboardingStatus = if ($device.onboardingStatus) { $device.onboardingStatus } else { "Unknown" }
        OSPlatform       = if ($device.osPlatform) { $device.osPlatform } else { "-" }
        OSDisplay        = if ($osDisplay) { $osDisplay } else { "-" }
        LastSeen         = $device.lastSeen
        LastIp           = $device.lastIpAddress
    }
}
$results = $results | Sort-Object DeviceName

# Export CSV
$csvPath = Join-Path $OutputFolder "MDE_DeviceHealth_$timestamp.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation

# Calculate stats
$total = $results.Count
$active = ($results | Where-Object { $_.SensorState -eq "Active" }).Count
$inactive = ($results | Where-Object { $_.SensorState -eq "Inactive" }).Count
$onboarded = ($results | Where-Object { $_.OnboardingStatus -eq "Onboarded" }).Count
$activePct = if ($total -gt 0) { [math]::Round(($active / $total) * 100, 1) } else { 0 }
$onboardedPct = if ($total -gt 0) { [math]::Round(($onboarded / $total) * 100, 1) } else { 0 }
$healthScore = [math]::Round((($activePct + $onboardedPct) / 2), 0)
$reportDate = Get-Date -Format "MMMM dd, yyyy HH:mm:ss"

# Problem devices
$problemDevices = $results | Where-Object { $_.SensorState -eq "Inactive" } | Select-Object -First 10

# Generate HTML
$healthColor = if ($healthScore -ge 80) { "#10b981" } elseif ($healthScore -ge 60) { "#f59e0b" } else { "#ef4444" }
$healthLabel = if ($healthScore -ge 80) { "Healthy" } elseif ($healthScore -ge 60) { "Fair" } else { "Needs Attention" }

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MDE Device Health Report</title>
<style>
:root {
    --bg-primary: #0f0f1a;
    --bg-secondary: #1a1a2e;
    --bg-card: rgba(255,255,255,0.05);
    --border-color: rgba(255,255,255,0.1);
    --text-primary: #e8e8e8;
    --text-secondary: rgba(255,255,255,0.7);
    --accent-blue: #0078d4;
    --accent-green: #10b981;
    --accent-red: #ef4444;
    --accent-yellow: #f59e0b;
    --accent-purple: #8b5cf6;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', -apple-system, sans-serif; background: linear-gradient(135deg, var(--bg-primary) 0%, var(--bg-secondary) 50%, #16213e 100%); color: var(--text-primary); min-height: 100vh; padding: 30px; }
.container { max-width: 1800px; margin: 0 auto; }

/* Header */
.header { background: linear-gradient(135deg, #0078d4 0%, #106ebe 50%, #005a9e 100%); border-radius: 20px; padding: 40px; margin-bottom: 30px; box-shadow: 0 15px 50px rgba(0,120,212,0.3); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 20px; }
.header-content h1 { font-size: 2.4em; font-weight: 700; margin-bottom: 8px; letter-spacing: -0.5px; }
.header-content .subtitle { font-size: 1.1em; opacity: 0.9; margin-bottom: 15px; }
.header-content .meta { font-size: 0.9em; opacity: 0.75; display: flex; gap: 20px; flex-wrap: wrap; }
.header-content .meta span { display: flex; align-items: center; gap: 6px; }
.header-actions { display: flex; gap: 12px; }
.btn { padding: 12px 24px; border-radius: 10px; font-size: 0.9em; font-weight: 600; cursor: pointer; transition: all 0.2s; border: none; display: flex; align-items: center; gap: 8px; }
.btn-primary { background: white; color: #0078d4; }
.btn-primary:hover { transform: translateY(-2px); box-shadow: 0 8px 20px rgba(0,0,0,0.2); }
.btn-secondary { background: rgba(255,255,255,0.15); color: white; border: 1px solid rgba(255,255,255,0.3); }
.btn-secondary:hover { background: rgba(255,255,255,0.25); }

/* Health Score */
.health-score { text-align: center; background: rgba(0,0,0,0.2); border-radius: 16px; padding: 25px 35px; }
.health-score .score { font-size: 3.5em; font-weight: 800; line-height: 1; }
.health-score .label { font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; margin-top: 5px; opacity: 0.9; }

/* Stats Row */
.stats-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 30px; }
.stat-mini { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 12px; padding: 20px; text-align: center; cursor: pointer; transition: all 0.2s; }
.stat-mini:hover { transform: translateY(-3px); border-color: var(--accent-blue); }
.stat-mini .value { font-size: 2em; font-weight: 700; line-height: 1; margin-bottom: 5px; }
.stat-mini .label { font-size: 0.75em; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-secondary); }

/* Dashboard Grid */
.dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 25px; margin-bottom: 30px; }

/* Cards */
.card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 16px; padding: 25px; backdrop-filter: blur(10px); }
.card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
.card-title { font-size: 1em; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-secondary); }
.card-icon { width: 40px; height: 40px; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.2em; }

/* Progress Bars */
.progress-container { margin-top: 15px; }
.progress-label { display: flex; justify-content: space-between; font-size: 0.85em; margin-bottom: 8px; }
.progress-label span:last-child { font-weight: 600; }
.progress-bar { height: 10px; background: rgba(255,255,255,0.1); border-radius: 5px; overflow: hidden; }
.progress-fill { height: 100%; border-radius: 5px; transition: width 0.5s ease; }
.progress-fill.green { background: linear-gradient(90deg, #10b981, #34d399); }
.progress-fill.blue { background: linear-gradient(90deg, #0078d4, #38bdf8); }

/* Donut Chart */
.donut-container { display: flex; align-items: center; gap: 30px; }
.donut { width: 140px; height: 140px; border-radius: 50%; position: relative; display: flex; align-items: center; justify-content: center; }
.donut-center { position: absolute; width: 90px; height: 90px; background: var(--bg-secondary); border-radius: 50%; display: flex; flex-direction: column; align-items: center; justify-content: center; }
.donut-center .value { font-size: 1.8em; font-weight: 700; }
.donut-center .label { font-size: 0.7em; color: var(--text-secondary); text-transform: uppercase; }
.donut-legend { display: flex; flex-direction: column; gap: 12px; }
.legend-item { display: flex; align-items: center; gap: 10px; font-size: 0.9em; }
.legend-dot { width: 12px; height: 12px; border-radius: 3px; }

/* Attention Section */
.attention-card { border-left: 4px solid var(--accent-yellow); }
.attention-card .card-icon { background: rgba(245,158,11,0.15); color: var(--accent-yellow); }
.attention-list { list-style: none; }
.attention-item { display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid var(--border-color); }
.attention-item:last-child { border-bottom: none; }
.attention-item .device { font-weight: 500; }
.issue-badge { font-size: 0.75em; padding: 4px 10px; border-radius: 20px; font-weight: 600; background: rgba(239,68,68,0.15); color: var(--accent-red); }

/* Table Section */
.table-section { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 16px; padding: 25px; margin-bottom: 30px; }
.table-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 15px; }
.table-title { font-size: 1.2em; font-weight: 600; }
.filters { display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-end; }
.filter-group { display: flex; flex-direction: column; gap: 5px; }
.filter-group label { font-size: 0.7em; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-secondary); }
.filter-group input, .filter-group select { padding: 10px 14px; background: rgba(255,255,255,0.05); border: 1px solid var(--border-color); border-radius: 8px; color: var(--text-primary); font-size: 0.9em; min-width: 140px; }
.filter-group input:focus, .filter-group select:focus { outline: none; border-color: var(--accent-blue); box-shadow: 0 0 0 3px rgba(0,120,212,0.2); }
.filter-group select option { background: var(--bg-secondary); }
.results-info { font-size: 0.9em; color: var(--text-secondary); margin-bottom: 15px; }

/* Table */
.table-wrapper { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; min-width: 800px; }
th, td { padding: 14px 16px; text-align: left; border-bottom: 1px solid var(--border-color); }
th { background: rgba(0,120,212,0.1); font-weight: 600; text-transform: uppercase; font-size: 0.75em; letter-spacing: 0.5px; cursor: pointer; user-select: none; white-space: nowrap; }
th:hover { background: rgba(0,120,212,0.2); }
th.sorted-asc::after { content: ' ▲'; color: var(--accent-blue); }
th.sorted-desc::after { content: ' ▼'; color: var(--accent-blue); }
tbody tr { transition: background 0.15s; }
tbody tr:hover { background: rgba(255,255,255,0.03); }
td { font-size: 0.9em; }
td.ip { font-family: 'Consolas', 'Monaco', monospace; font-size: 0.85em; color: var(--text-secondary); }

/* Status Badges */
.status { padding: 5px 12px; border-radius: 20px; font-size: 0.8em; font-weight: 600; display: inline-block; white-space: nowrap; }
.status.active { background: rgba(16,185,129,0.15); color: var(--accent-green); }
.status.inactive { background: rgba(239,68,68,0.15); color: var(--accent-red); }
.status.onboarded { background: rgba(0,120,212,0.15); color: var(--accent-blue); }
.status.canbe { background: rgba(245,158,11,0.15); color: var(--accent-yellow); }
.status.insuffinfo { background: rgba(139,92,246,0.15); color: var(--accent-purple); }
.status.unsupported { background: rgba(107,114,128,0.15); color: #9ca3af; }
.status.unknown { background: rgba(107,114,128,0.15); color: #9ca3af; }

/* Footer */
.footer { text-align: center; padding: 30px; color: var(--text-secondary); font-size: 0.85em; }

@media print {
    body { background: white; color: black; padding: 20px; }
    .btn, .filters { display: none !important; }
    .card, .table-section { border: 1px solid #ddd; box-shadow: none; }
    .header { background: #0078d4 !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div class="header-content">
            <h1>MDE Device Health Report</h1>
            <div class="subtitle">Microsoft Defender for Endpoint - API Only</div>
            <div class="meta">
                <span>&#128197; $reportDate</span>
                <span>&#127760; $Environment</span>
                <span>&#128187; $total Devices</span>
            </div>
        </div>
        <div class="health-score">
            <div class="score" style="color: $healthColor">$healthScore%</div>
            <div class="label">$healthLabel</div>
        </div>
        <div class="header-actions">
            <button class="btn btn-primary" onclick="exportCSV()">&#128202; Export CSV</button>
        </div>
    </div>

    <div class="stats-row">
        <div class="stat-mini" onclick="clearFilters()">
            <div class="value" style="color: var(--accent-blue)">$total</div>
            <div class="label">Total Devices</div>
        </div>
        <div class="stat-mini" onclick="quickFilter('sensor', 'Active')">
            <div class="value" style="color: var(--accent-green)">$active</div>
            <div class="label">Sensor Active</div>
        </div>
        <div class="stat-mini" onclick="quickFilter('sensor', 'Inactive')">
            <div class="value" style="color: var(--accent-red)">$inactive</div>
            <div class="label">Sensor Inactive</div>
        </div>
        <div class="stat-mini" onclick="quickFilter('onboarding', 'Onboarded')">
            <div class="value" style="color: var(--accent-blue)">$onboarded</div>
            <div class="label">Onboarded</div>
        </div>
    </div>

    <div class="dashboard">
        <div class="card">
            <div class="card-header">
                <span class="card-title">Sensor Health</span>
                <div class="card-icon" style="background: rgba(16,185,129,0.15); color: var(--accent-green);">&#128737;</div>
            </div>
            <div class="donut-container">
                <div class="donut" style="background: conic-gradient(var(--accent-green) 0deg $($activePct * 3.6)deg, var(--accent-red) $($activePct * 3.6)deg 360deg);">
                    <div class="donut-center">
                        <div class="value">$activePct%</div>
                        <div class="label">Active</div>
                    </div>
                </div>
                <div class="donut-legend">
                    <div class="legend-item"><div class="legend-dot" style="background: var(--accent-green);"></div>Active: $active</div>
                    <div class="legend-item"><div class="legend-dot" style="background: var(--accent-red);"></div>Inactive: $inactive</div>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <span class="card-title">Onboarding Status</span>
                <div class="card-icon" style="background: rgba(0,120,212,0.15); color: var(--accent-blue);">&#128274;</div>
            </div>
            <div class="progress-container">
                <div class="progress-label"><span>Onboarded</span><span>$onboarded / $total ($onboardedPct%)</span></div>
                <div class="progress-bar"><div class="progress-fill blue" style="width: $onboardedPct%;"></div></div>
            </div>
            <div class="progress-container">
                <div class="progress-label"><span>Sensor Active</span><span>$active / $total ($activePct%)</span></div>
                <div class="progress-bar"><div class="progress-fill $(if ($activePct -ge 90) { 'green' } else { 'blue' })" style="width: $activePct%;"></div></div>
            </div>
        </div>

        <div class="card attention-card">
            <div class="card-header">
                <span class="card-title">&#9888; Needs Attention</span>
                <div class="card-icon">&#9889;</div>
            </div>
            <ul class="attention-list">
"@

if ($problemDevices.Count -gt 0) {
    foreach ($p in $problemDevices) {
        $displayName = if ($p.DeviceName.Length -gt 30) { $p.DeviceName.Substring(0,27) + "..." } else { $p.DeviceName }
        $html += @"
                <li class="attention-item">
                    <span class="device">$displayName</span>
                    <span class="issue-badge">Sensor Off</span>
                </li>
"@
    }
    $remaining = $inactive - 10
    if ($remaining -gt 0) {
        $html += @"
                <li class="attention-item" style="color: var(--text-secondary); font-size: 0.9em;">
                    <span>+ $remaining more devices need attention</span>
                </li>
"@
    }
} else {
    $html += @"
                <li class="attention-item" style="color: var(--accent-green);">
                    <span>&#10003; All devices healthy!</span>
                </li>
"@
}

$html += @"
            </ul>
        </div>
    </div>

    <div class="table-section">
        <div class="table-header">
            <span class="table-title">&#128203; Device Inventory</span>
            <div class="filters">
                <div class="filter-group">
                    <label>Device Name</label>
                    <input type="text" id="filterName" placeholder="Search..." onkeyup="applyFilters()">
                </div>
                <div class="filter-group">
                    <label>Sensor</label>
                    <select id="filterSensor" onchange="applyFilters()">
                        <option value="">All</option>
                        <option value="Active">Active</option>
                        <option value="Inactive">Inactive</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label>Onboarding</label>
                    <select id="filterOnboard" onchange="applyFilters()">
                        <option value="">All</option>
                        <option value="Onboarded">Onboarded</option>
                        <option value="CanBeOnboarded">Can Be Onboarded</option>
                        <option value="InsufficientInfo">Insufficient Info</option>
                        <option value="Unsupported">Unsupported</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label>OS Platform</label>
                    <select id="filterOS" onchange="applyFilters()">
                        <option value="">All</option>
                        <option value="Windows">Windows</option>
                        <option value="Linux">Linux</option>
                        <option value="macOS">macOS</option>
                        <option value="Android">Android</option>
                        <option value="iOS">iOS</option>
                    </select>
                </div>
                <button class="btn btn-secondary" onclick="clearFilters()" style="padding: 10px 16px;">Clear</button>
            </div>
        </div>
        <div class="results-info">
            <span id="resultsCount">Showing $total of $total devices</span>
        </div>
        <div class="table-wrapper">
            <table id="deviceTable">
                <thead>
                    <tr>
                        <th onclick="sortTable(0)">Device Name</th>
                        <th onclick="sortTable(1)">Sensor State</th>
                        <th onclick="sortTable(2)">Onboarding</th>
                        <th onclick="sortTable(3)">Operating System</th>
                        <th onclick="sortTable(4)">Last IP</th>
                        <th onclick="sortTable(5)">Last Seen</th>
                    </tr>
                </thead>
                <tbody>
"@

foreach ($r in $results) {
    $sensorClass = switch ($r.SensorState) { "Active" { "active" } "Inactive" { "inactive" } default { "unknown" } }
    $onboardClass = switch ($r.OnboardingStatus) { 
        "Onboarded" { "onboarded" } 
        "CanBeOnboarded" { "canbe" } 
        "InsufficientInfo" { "insuffinfo" }
        "Unsupported" { "unsupported" }
        default { "unknown" } 
    }
    $lastSeen = if ($r.LastSeen) { ([datetime]$r.LastSeen).ToString("yyyy-MM-dd HH:mm") } else { "-" }
    $lastIp = if ($r.LastIp) { $r.LastIp } else { "-" }
    $html += @"
                    <tr data-os="$($r.OSPlatform)">
                        <td><strong>$($r.DeviceName)</strong></td>
                        <td><span class="status $sensorClass">$($r.SensorState)</span></td>
                        <td><span class="status $onboardClass">$($r.OnboardingStatus)</span></td>
                        <td>$($r.OSDisplay)</td>
                        <td class="ip">$lastIp</td>
                        <td>$lastSeen</td>
                    </tr>
"@
}

$html += @"
                </tbody>
            </table>
        </div>
    </div>

    <div class="footer">
        <p>Generated by <strong>MDE Device Health Export Tool</strong> | Microsoft Defender for Endpoint</p>
    </div>
</div>

<script>
const totalDevices = $total;
let sortCol = -1;
let sortAsc = true;

function applyFilters() {
    const filterName = document.getElementById('filterName').value.toLowerCase();
    const filterSensor = document.getElementById('filterSensor').value;
    const filterOnboard = document.getElementById('filterOnboard').value;
    const filterOS = document.getElementById('filterOS').value.toLowerCase();
    
    const rows = document.querySelectorAll('#deviceTable tbody tr');
    let visibleCount = 0;
    
    rows.forEach(row => {
        const cells = row.getElementsByTagName('td');
        const name = cells[0].textContent.toLowerCase();
        const sensor = cells[1].textContent.trim();
        const onboarding = cells[2].textContent.trim();
        const os = (row.getAttribute('data-os') || '').toLowerCase();
        
        let show = true;
        if (filterName && !name.includes(filterName)) show = false;
        if (filterSensor && sensor !== filterSensor) show = false;
        if (filterOnboard && onboarding !== filterOnboard) show = false;
        if (filterOS && !os.includes(filterOS)) show = false;
        
        row.style.display = show ? '' : 'none';
        if (show) visibleCount++;
    });
    
    document.getElementById('resultsCount').textContent = 'Showing ' + visibleCount + ' of ' + totalDevices + ' devices';
}

function clearFilters() {
    document.getElementById('filterName').value = '';
    document.getElementById('filterSensor').value = '';
    document.getElementById('filterOnboard').value = '';
    document.getElementById('filterOS').value = '';
    applyFilters();
}

function quickFilter(type, value) {
    clearFilters();
    if (type === 'sensor') document.getElementById('filterSensor').value = value;
    else if (type === 'onboarding') document.getElementById('filterOnboard').value = value;
    else if (type === 'os') document.getElementById('filterOS').value = value;
    applyFilters();
}

function sortTable(colIndex) {
    const table = document.getElementById('deviceTable');
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const headers = table.querySelectorAll('th');
    
    if (sortCol === colIndex) sortAsc = !sortAsc;
    else { sortCol = colIndex; sortAsc = true; }
    
    headers.forEach((h, i) => {
        h.classList.remove('sorted-asc', 'sorted-desc');
        if (i === colIndex) h.classList.add(sortAsc ? 'sorted-asc' : 'sorted-desc');
    });
    
    rows.sort((a, b) => {
        const aVal = a.cells[colIndex].textContent.toLowerCase();
        const bVal = b.cells[colIndex].textContent.toLowerCase();
        return sortAsc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
    });
    
    rows.forEach(row => tbody.appendChild(row));
}

function exportCSV() {
    const rows = document.querySelectorAll('#deviceTable tr');
    let csv = [];
    rows.forEach(row => {
        const cols = row.querySelectorAll('td, th');
        const rowData = Array.from(cols).map(col => '"' + col.textContent.replace(/"/g, '""').trim() + '"');
        csv.push(rowData.join(','));
    });
    const blob = new Blob([csv.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'MDE_DeviceHealth_Export.csv';
    a.click();
}
</script>
</body>
</html>
"@

$htmlPath = Join-Path $OutputFolder "MDE_DeviceHealth_$timestamp.html"
$html | Out-File -FilePath $htmlPath -Encoding UTF8

# Summary
Write-Host ""
Write-Host "  +================================================================+" -ForegroundColor Cyan
Write-Host "  |                        SUMMARY                                 |" -ForegroundColor Cyan
Write-Host "  +================================================================+" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Total Devices:    $total" -ForegroundColor White
Write-Host "  Sensor Active:    $active ($activePct%)" -ForegroundColor Green
Write-Host "  Sensor Inactive:  $inactive" -ForegroundColor $(if ($inactive -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Onboarded:        $onboarded ($onboardedPct%)" -ForegroundColor Green
Write-Host ""
Write-Host "  Output:" -ForegroundColor Yellow
Write-Host "  CSV:  $csvPath" -ForegroundColor White
Write-Host "  HTML: $htmlPath" -ForegroundColor White
Write-Host ""
