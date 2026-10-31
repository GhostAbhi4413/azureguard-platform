param(
    [string]$Server = 'localhost,1433',
    [string]$Database = 'AzureGuard'
)

$ErrorActionPreference = 'Stop'
if ($Database -notmatch '^[A-Za-z][A-Za-z0-9_]{0,127}$') { throw 'Database name must be a simple SQL identifier.' }
$sqlcmd = Get-Command sqlcmd -ErrorAction SilentlyContinue
if (-not $sqlcmd) { throw 'sqlcmd was not found. Install Microsoft sqlcmd or apply the scripts with SQL Server Management Studio.' }

$auth = @('-E')
if ($env:SQL_USER) {
    if (-not $env:SQL_PASSWORD) { throw 'Set SQL_PASSWORD when SQL_USER is configured.' }
    $auth = @('-U', $env:SQL_USER, '-P', $env:SQL_PASSWORD)
}

Write-Host "Creating database '$Database' only if it does not already exist..."
& $sqlcmd.Source -S $Server @auth -C -b -d master -Q "IF DB_ID(N'$Database') IS NULL EXEC(N'CREATE DATABASE [$Database]')"
if ($LASTEXITCODE -ne 0) { throw "Could not connect/create database (sqlcmd exit $LASTEXITCODE)." }

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$scriptDirectory = Join-Path $repositoryRoot 'backend/database'
foreach ($name in @('001_initial_schema.sql', '002_add_auth_password_hash.sql', '003_phase1_release_core.sql')) {
    $file = Join-Path $scriptDirectory $name
    if (-not (Test-Path -LiteralPath $file)) { throw "Required SQL script is missing: $file" }
    Write-Host "Applying $name to $Database..."
    & $sqlcmd.Source -S $Server @auth -C -b -d $Database -i $file
    if ($LASTEXITCODE -ne 0) { throw "Applying $name failed (sqlcmd exit $LASTEXITCODE). No database was dropped." }
}
Write-Host 'AzureGuard local SQL schema setup completed. Existing rows were not deleted.'
