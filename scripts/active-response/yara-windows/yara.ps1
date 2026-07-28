<#
    Wazuh Active Response - YARA scan and delete (Windows).

    Launched by yara.bat when a FIM rule fires. Reads the execd alert JSON
    from STDIN, scans the changed file with yara64.exe, and deletes it on a
    positive match.

    Deploy to: <AGENT_PATH>\active-response\bin\yara.ps1
    Logs to:   <AGENT_PATH>\active-response\active-responses.log

    Run ".\yara.ps1 -SelfTest" to exercise the JSON parsing and the
    delete-with-retry logic without a Wazuh agent or YARA present.
#>

param([switch]$SelfTest)

# Resolve AGENT_PATH from this script's own location rather than guessing it
# from PROCESSOR_ARCHITECTURE. The architecture check in the PoC script picks
# the wrong "Program Files" directory whenever the agent bitness and the host
# bitness disagree.
$binDir            = $PSScriptRoot
$activeResponseDir = Split-Path -Parent $binDir
$AGENT_PATH        = Split-Path -Parent $activeResponseDir

$LOG_FILE   = Join-Path $AGENT_PATH "active-response\active-responses.log"
$YARA_EXE   = Join-Path $AGENT_PATH "active-response\bin\yara\yara64.exe"
$YARA_RULES = Join-Path $AGENT_PATH "active-response\bin\yara\rules\yara_rules.yar"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
    "$timestamp wazuh-yara: $Message" | Out-File -Append -Encoding utf8 -FilePath $LOG_FILE
}

function Get-SyscheckPath {
    # Extract the changed file path from an execd active-response message.
    # Returns $null for empty or malformed input so the caller can log a
    # specific error instead of raising an exception.
    param([string]$Json)
    if ([string]::IsNullOrWhiteSpace($Json)) { return $null }
    try {
        return ($Json | ConvertFrom-Json).parameters.alert.syscheck.path
    } catch {
        return $null
    }
}

function Wait-FileStable {
    # Block until the file size stops changing, so YARA does not scan a
    # half-written download. Returns $false if the file vanishes.
    param([string]$Path, [int]$MaxWaitSeconds = 15)

    $prevSize = -1
    $stableCount = 0
    $waited = 0

    while ($stableCount -lt 2 -and $waited -lt $MaxWaitSeconds) {
        $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
        if ($null -eq $item) { return $false }

        if ($item.Length -eq $prevSize) {
            $stableCount++
        } else {
            $stableCount = 0
            $prevSize = $item.Length
        }

        if ($stableCount -lt 2) {
            Start-Sleep -Seconds 1
            $waited++
        }
    }
    return $true
}

function Remove-FileWithRetry {
    # Retry the delete: an AV real-time scanner or the downloading process
    # often still holds a handle for a second or two after the FIM event.
    param([string]$Path, [int]$MaxRetries = 5, [int]$DelaySeconds = 1)

    for ($i = 1; $i -le $MaxRetries; $i++) {
        if (-not (Test-Path -LiteralPath $Path)) { return $true }
        try {
            Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
            return $true
        } catch {
            Write-Log "WARNING - Delete attempt $i failed: $($_.Exception.GetType().FullName): $($_.Exception.Message)"
            Start-Sleep -Seconds $DelaySeconds
        }
    }
    return (-not (Test-Path -LiteralPath $Path))
}

# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
if ($SelfTest) {
    $LOG_FILE = Join-Path ([System.IO.Path]::GetTempPath()) "yara-selftest.log"

    function Assert {
        param([bool]$Condition, [string]$Name)
        if (-not $Condition) { throw "FAIL: $Name" }
        Write-Host "ok - $Name"
    }

    $sample = '{"version":1,"origin":{"name":"node01","module":"wazuh-execd"},' +
              '"command":"add","parameters":{"extra_args":[],"alert":{"rule":{"id":"100011"},' +
              '"syscheck":{"path":"C:\\Users\\jdoe\\Downloads\\eicar.com"}},' +
              '"program":"active-response/bin/yara.bat"}}'

    Assert ((Get-SyscheckPath $sample) -eq 'C:\Users\jdoe\Downloads\eicar.com') "parses syscheck.path from execd JSON"
    Assert ($null -eq (Get-SyscheckPath ""))                                     "empty STDIN yields no path"

    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "yara-selftest-target.tmp"
    Set-Content -LiteralPath $tmp -Value "eicar-stand-in" -Encoding ascii
    Assert (Wait-FileStable -Path $tmp)                        "stable file passes the stabilization wait"
    Assert (Remove-FileWithRetry -Path $tmp)                   "deletes an unlocked file"
    Assert (-not (Test-Path -LiteralPath $tmp))                "target is gone after delete"
    Assert (Remove-FileWithRetry -Path $tmp)                   "already-absent file counts as deleted"
    Assert (-not (Wait-FileStable -Path $tmp -MaxWaitSeconds 2)) "missing file fails the stabilization wait"

    Write-Host "self-test passed"
    exit 0
}

# ---------------------------------------------------------------------------
# Active response
# ---------------------------------------------------------------------------
Write-Log "----------------------------------------------------"

try {
    # Wazuh execd writes one newline-terminated JSON line to STDIN and keeps
    # the pipe open for a possible later handshake. ReadToEnd() waits for a
    # close that never comes and hangs the response; ReadLine() returns as
    # soon as the line arrives.
    $rawInput = [Console]::In.ReadLine()

    $syscheckFile = Get-SyscheckPath $rawInput

    if ([string]::IsNullOrWhiteSpace($rawInput)) {
        Write-Log "ERROR - No input received on STDIN."
        exit 1
    }

    Write-Log "File: [$syscheckFile]"

    if ([string]::IsNullOrWhiteSpace($syscheckFile)) {
        Write-Log "ERROR - Could not parse syscheck.path from JSON."
        exit 1
    }
    if (-not (Test-Path -LiteralPath $syscheckFile)) {
        Write-Log "ERROR - File not found."
        exit 1
    }
    if (-not (Wait-FileStable -Path $syscheckFile)) {
        Write-Log "ERROR - File disappeared while waiting for stabilization."
        exit 1
    }
    if (-not (Test-Path -LiteralPath $YARA_EXE)) {
        Write-Log "ERROR - yara64.exe not found at $YARA_EXE"
        exit 1
    }
    if (-not (Test-Path -LiteralPath $YARA_RULES)) {
        Write-Log "ERROR - Rules file not found at $YARA_RULES"
        exit 1
    }

    $yaraOutput = & $YARA_EXE $YARA_RULES $syscheckFile 2>&1
    $yaraExit = $LASTEXITCODE

    # Match vs. no-match is decided from the output below, not the exit code.
    # Codes of 2 and above mean YARA itself failed (bad rule syntax,
    # unreadable file), so surface its output rather than reporting a clean
    # scan.
    if ($yaraExit -ge 2) {
        Write-Log "ERROR - Failed to execute YARA (exit code $yaraExit)."
        foreach ($line in $yaraOutput) { Write-Log "YARA output: $line" }
        exit 1
    }

    $matchLines = @($yaraOutput | Where-Object { $_ -and $_.ToString().Trim() -ne "" })

    if ($matchLines.Count -eq 0) {
        Write-Log "INFO - No malware detected."
        exit 0
    }

    # Keep this wording verbatim: the yara_decoder regex on the manager keys
    # off "INFO - Scan result: <rule> <file>".
    foreach ($line in $matchLines) {
        Write-Log "INFO - Scan result: $line"
    }

    Write-Log "INFO - Attempting to delete file..."

    if (Remove-FileWithRetry -Path $syscheckFile) {
        Write-Log "INFO - Successfully deleted file: $syscheckFile"
        exit 0
    }

    Write-Log "ERROR - Failed to delete file after 5 attempts: $syscheckFile"
    exit 1

} catch {
    Write-Log "ERROR - Unhandled exception: $($_.Exception.GetType().FullName): $($_.Exception.Message)"
    exit 1
}
