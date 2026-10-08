@echo off
title CyberShield - Web Security System
echo ========================================================
echo   CyberShield: Phishing Detection System Starting...
echo   Open your browser at: http://localhost:8085/
echo ========================================================
timeout /t 3 >nul
start "" "http://localhost:8085/"
"C:\Users\USER\.gemini\antigravity\scratch\maven\apache-maven-3.9.6\bin\mvn.cmd" spring-boot:run
pause
