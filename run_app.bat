@echo off
title JuiceSec Analyzer - OWASP Juice Shop Vulnerability Scanner
chcp 65001 > nul
echo ============================================================
echo   JUICESEC ANALYZER - UNG DUNG PHAN TICH LO HONG JUICE SHOP
echo   Khoa An Toan Thong Tin - Hoc Vien Cong Nghe Buu Chinh Vien Thong
echo ============================================================
echo.
echo Dang khoi dong may chu phan tich tai http://127.0.0.1:5000...
start http://127.0.0.1:5000
python app\server.py 5000
pause
