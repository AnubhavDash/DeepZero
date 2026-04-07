$workDir = "d:\projects\byovd-agent\work"
$reportsDir = "d:\projects\byovd-agent\reports"

# 1. Migrate any legacy loose reports to session_0
$looseReports = Get-ChildItem -Path $reportsDir -Filter "*.md" -File
if ($looseReports.Count -gt 0) {
    if (-not (Test-Path "$reportsDir\session_0")) {
        New-Item -ItemType Directory -Path "$reportsDir\session_0" | Out-Null
    }
    $looseReports | Move-Item -Destination "$reportsDir\session_0"
    Write-Host "Migrated $($looseReports.Count) legacy reports to session_0"
}

# 2. Get all previously copied work IDs
$copiedWorkIds = @()
Get-ChildItem -Path $reportsDir -Recurse -Filter "*.md" -File | ForEach-Object {
    $copiedWorkIds += $_.BaseName
}

# 3. Find completely new work IDs
$newReports = @()
Get-ChildItem -Path $workDir -Directory | ForEach-Object {
    $id = $_.Name
    $report = Join-Path $_.FullName "VULNERABLE_report.md"
    
    if (-not (Test-Path $report)) { return }
    if ($copiedWorkIds -contains $id) { return }
    
    $newReports += $_
}

if ($newReports.Count -eq 0) {
    Write-Host "No new vulnerable reports to copy."
    exit
}

# 4. Determine next session directory
$sessionDirs = Get-ChildItem -Path $reportsDir -Directory -Filter "session_*"
$nextSessionIdx = 0
if ($sessionDirs.Count -gt 0) {
    $highest = 0
    foreach ($dir in $sessionDirs) {
        if ($dir.Name -match "session_(\d+)") {
            $num = [int]$matches[1]
            if ($num -ge $highest) { $highest = $num }
        }
    }
    $nextSessionIdx = $highest + 1
}

$newSessionDir = Join-Path $reportsDir "session_$nextSessionIdx"
New-Item -ItemType Directory -Path $newSessionDir | Out-Null

# 5. Process and copy new reports
$copied = 0
foreach ($dir in $newReports) {
    $id = $dir.Name
    $report = Join-Path $dir.FullName "VULNERABLE_report.md"
    $stdout = Join-Path $dir.FullName "ghidra_stdout.log"

    # extract driver path from ghidra stdout
    $driverPath = ""
    if (Test-Path $stdout) {
        $match = Select-String -Path $stdout -Pattern "IMPORTING: file:///(.+?) \(" -List
        if ($match) {
            $driverPath = $match.Matches[0].Groups[1].Value
        }
    }

    $dispatchPath = Join-Path $dir.FullName "decompiled\dispatch_ioctl.c"

    # build the output with file path header + original report
    $content = Get-Content $report -Raw
    $headers = @()
    if ($driverPath) {
        $headers += "**Driver Path:** ``$driverPath```n"
    }
    if (Test-Path $dispatchPath) {
        $headers += "**Dispatch C:** ``$dispatchPath```n"
    }
    if ($headers.Count -gt 0) {
        $headerStr = $headers -join ""
        $content = "$headerStr`n---`n`n$content"
    }

    Set-Content -Path (Join-Path $newSessionDir "$id.md") -Value $content -NoNewline
    $copied++
}

Write-Host "Done. Copied $copied new reports to $newSessionDir"
