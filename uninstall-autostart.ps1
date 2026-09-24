# MiMo Relay 开机自启卸载
$ErrorActionPreference = 'SilentlyContinue'
$taskName = 'MimoRelay'
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $taskName
$stateDir = Join-Path $env:APPDATA 'mimo-relay'
# 停掉正在跑的 relay(命令行含 mimo-relay.cjs 的 node 进程)
Get-CimInstance Win32_Process -Filter "Name='node.exe'" |
  Where-Object { $_.CommandLine -like '*mimo-relay.cjs*' } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Remove-Item (Join-Path $stateDir 'run-hidden.vbs') -Force
Write-Host "[+] removed Run key '$taskName', stopped running relay, deleted run-hidden.vbs"
Write-Host "[=] kept: $stateDir\creds.dat (DPAPI credential cache) and relay.log; delete manually if desired"
