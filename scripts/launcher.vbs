' RMS Monitor Launcher — Launches monitor.ps1 with ZERO visible window.
' wscript.exe natively supports hiding child processes via Run(..., 0, False).
' This bypasses Windows Terminal completely.
CreateObject("Wscript.Shell").Run "powershell.exe -NonInteractive -NoProfile -NoLogo -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\RMS\monitor.ps1", 0, False
