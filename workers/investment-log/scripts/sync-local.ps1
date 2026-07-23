[CmdletBinding()]
param(
    [string]$Database = "sumsec-investment-log",
    [string]$OutputDirectory
)

$ErrorActionPreference = "Stop"
$workerDirectory = Split-Path -Parent $PSScriptRoot
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $workerDirectory "local-data"
}

$outputPath = [System.IO.Path]::GetFullPath($OutputDirectory)
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$archiveSql = Join-Path $outputPath "$Database-$timestamp.sql"
$latestSql = Join-Path $outputPath "latest.sql"
$latestSqlite = Join-Path $outputPath "latest.sqlite"
$importScript = Join-Path $PSScriptRoot "import-d1-sql.py"
New-Item -ItemType Directory -Force -Path $outputPath | Out-Null

$proxyNames = @("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")
$savedProxies = @{}
foreach ($name in $proxyNames) {
    $savedProxies[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
    Remove-Item "Env:$name" -ErrorAction SilentlyContinue
}

Push-Location $workerDirectory
try {
    & npx wrangler d1 export $Database --remote --output $archiveSql
    if ($LASTEXITCODE -ne 0) {
        throw "Cloudflare D1 export failed with exit code $LASTEXITCODE"
    }

    $pythonLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pythonLauncher) {
        & $pythonLauncher.Source -3 $importScript --input $archiveSql --output $latestSqlite
    } else {
        & python $importScript --input $archiveSql --output $latestSqlite
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Local SQLite import failed with exit code $LASTEXITCODE"
    }

    Copy-Item -LiteralPath $archiveSql -Destination $latestSql -Force
    Write-Host "SQL backup: $archiveSql"
    Write-Host "Latest SQL: $latestSql"
    Write-Host "Latest SQLite: $latestSqlite"
} finally {
    Pop-Location
    foreach ($name in $proxyNames) {
        $value = $savedProxies[$name]
        if ($null -eq $value) {
            Remove-Item "Env:$name" -ErrorAction SilentlyContinue
        } else {
            [Environment]::SetEnvironmentVariable($name, $value, "Process")
        }
    }
}
