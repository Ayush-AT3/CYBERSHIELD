Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Starting CyberShield: Smart Web Security System" -ForegroundColor Green
Write-Host "  Final Year Project - Phishing Detection Engine" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$mavenCmd = Join-Path $PSScriptRoot "..\maven\apache-maven-3.9.6\bin\mvn.cmd"

if (Test-Path $mavenCmd) {
    & $mavenCmd spring-boot:run
} else {
    mvn spring-boot:run
}
