param(
    [string]$AdminUsername = $env:ADMIN_USERNAME,
    [string]$AdminEmail = $env:ADMIN_EMAIL,
    [string]$AdminPassword = $env:ADMIN_PASSWORD
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot

$javaVersion = (& java -version 2>&1 | Select-Object -First 1) -join ''
if ($javaVersion -notmatch '"21[\.]') {
    throw "Java 21 e obrigatorio. Versao encontrada: $javaVersion"
}

$mongoService = Get-Service -Name MongoDB -ErrorAction SilentlyContinue
if ($mongoService -and $mongoService.Status -ne 'Running') {
    Start-Service MongoDB
}

if ($AdminUsername -and $AdminEmail -and $AdminPassword) {
    $env:ADMIN_USERNAME = $AdminUsername
    $env:ADMIN_EMAIL = $AdminEmail
    $env:ADMIN_PASSWORD = $AdminPassword
}

Set-Location $projectRoot
& .\mvnw.cmd spring-boot:run
exit $LASTEXITCODE
