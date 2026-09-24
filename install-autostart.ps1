# MiMo Relay 开机自启安装(当前用户,无需管理员)
# 用法: powershell -ExecutionPolicy Bypass -File install-autostart.ps1
$ErrorActionPreference = 'Stop'
$taskName = 'MimoRelay'
$relayDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$relayJs  = Join-Path $relayDir 'mimo-relay.cjs'
if (-not (Test-Path $relayJs)) { Write-Error "mimo-relay.cjs not found next to this script: $relayJs" }

$node = (Get-Command node.exe -ErrorAction SilentlyContinue).Source
if (-not $node) { Write-Error 'node.exe not found in PATH (need Node.js >= 22.5 for node:sqlite)' }

$stateDir = Join-Path $env:APPDATA 'mimo-relay'
New-Item -ItemType Directory -Force $stateDir | Out-Null
$logPath = Join-Path $stateDir 'relay.log'
$vbsPath = Join-Path $stateDir 'run-hidden.vbs'

# wscript 隐藏窗口启动;日志经 MIMO_RELAY_LOG 落盘。VBScript 以 UTF-16 写入以兼容中文路径
$vbs = @"
Set sh = CreateObject("Wscript.Shell")
sh.Environment("PROCESS")("MIMO_RELAY_LOG") = "$logPath"
sh.Run """$node"" ""$relayJs""", 0, False
"@
[System.IO.File]::WriteAllText($vbsPath, $vbs, [System.Text.Encoding]::Unicode)

# 开机自启:当前用户注册表 Run 键(无需管理员,不触发计划任务权限策略)
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Set-ItemProperty -Path $runKey -Name $taskName -Value "wscript.exe `"$vbsPath`""
Write-Host "[+] installed: HKCU Run key '$taskName' (logon autostart, current user)"
Write-Host "[+] vbs:  $vbsPath"
Write-Host "[+] log:  $logPath"

# 立即启动一次(若 8317 已被占用则跳过)
$busy = $false
try { $c = New-Object System.Net.Sockets.TcpClient; $c.Connect('127.0.0.1', 8317); $c.Close(); $busy = $true } catch {}
if ($busy) {
  Write-Host '[=] port 8317 already in use, relay seems running; skip immediate start'
} else {
  Start-Process wscript.exe -ArgumentList "`"$vbsPath`"" -WindowStyle Hidden
  Start-Sleep -Seconds 4
  try { $h = Invoke-RestMethod -Uri 'http://127.0.0.1:8317/health' -TimeoutSec 5; Write-Host "[+] health: $($h | ConvertTo-Json -Compress)" }
  catch { Write-Host '[!] started but /health not ready yet; first run requires MiMo Desktop fully exited once (credential extraction)' }
}
Write-Host '[*] uninstall: powershell -ExecutionPolicy Bypass -File uninstall-autostart.ps1'
