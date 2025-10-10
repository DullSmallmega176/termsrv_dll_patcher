# PowerShell script used to patch termsrv.dll file and allow multiple RDP connections on Windows 10 (1809 and never) and Windows 11 
# Details here http://woshub.com/how-to-allow-multiple-rdp-sessions-in-windows-10/

# Checking OS version
Write-Output "Checking windows version..."
$osInfo = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$currentBuild = $osInfo.currentBuild
$displayVersion = $osInfo.displayVersion
if (-not $displayVersion) {
    Write-Host "Error: Could not determine Windows version." -ForegroundColor Red
    Write-Host "For your safety, this script will close in 5 seconds."
    Start-Sleep -Seconds 5
    Exit
}
Write-Output "Detected Windows Version: $displayVersion (Build $currentBuild)"
# Check if the OS version is a safe one to do the patch on.
if ($displayVersion -match '^\d{2}H\d$') {
    $version= [int]($displayVersion -replace 'H', '')
    if ($version -ge 242) {
        Write-Host "Error: Your Windows version ($displayVersion) is NOT supported." -ForegroundColor Red
        Write-Host "For your safety, this script will close in 5 seconds."
        Start-Sleep -Seconds 5
        Exit
    } else {
        Write-Output "Windows version is supported, proceeding."
    }
} else {
    Write-Output "Seems like your windows version format is weird. (not ##H# 'e.g. 24H2')"
}
# Stop RDP service, make a backup of the termsrv.dllfile and change the permissions 
Write-Output "Stopping Remote Desktop Services..."
Stop-Service UmRdpService -Force
Stop-Service TermService -Force
Write-Output "Making a copy termsrv.dll as termsrv.dll.copy"
$termsrv_dll_acl = Get-Acl c:\windows\system32\termsrv.dll
Copy-Item c:\windows\system32\termsrv.dll c:\windows\system32\termsrv.dll.copy
Write-Output "Taking ownership of termsrv.dll"
takeown /f c:\windows\system32\termsrv.dll
$new_termsrv_dll_owner = (Get-Acl c:\windows\system32\termsrv.dll).owner
cmd /c "icacls c:\windows\system32\termsrv.dll /Grant $($new_termsrv_dll_owner):F /C"
# search for a pattern in termsrv.dll file 
Write-Output "Searching for the string pattern to patch termsrv.dll"
$dll_as_bytes = Get-Content c:\windows\system32\termsrv.dll -Raw -Encoding byte
$dll_as_text = $dll_as_bytes.forEach('ToString', 'X2') -join ' '
$patternregex = ([regex]'39 81 3C 06 00 00(\s\S\S){6}')
$patch = 'B8 00 01 00 00 89 81 38 06 00 00 90'
$checkPattern=Select-String -Pattern $patternregex -InputObject $dll_as_text
If ($checkPattern -ne $null) {
    $dll_as_text_replaced = $dll_as_text -replace $patternregex, $patch
}
Elseif (Select-String -Pattern $patch -InputObject $dll_as_text) {
    Write-Output "termsrv.dll file is already patched, exiting script."
    Set-Acl c:\windows\system32\termsrv.dll $termsrv_dll_acl
    Start-Sleep -Seconds 5
    Exit
}
else { 
    Write-Output "Pattern not found, exiting script."
    Set-Acl c:\windows\system32\termsrv.dll $termsrv_dll_acl
    Start-Sleep -Seconds 5
    Exit
}
# patching termsrv.dll
Write-Output "Pattern was found, continuing to patching termsrv.dll"
[byte[]] $dll_as_bytes_replaced = -split $dll_as_text_replaced -replace '^', '0x'
Set-Content c:\windows\system32\termsrv.dll.patched -Encoding Byte -Value $dll_as_bytes_replaced
# comparing two files 
fc.exe /b c:\windows\system32\termsrv.dll.patched c:\windows\system32\termsrv.dll
# replacing the original termsrv.dll file 
Copy-Item c:\windows\system32\termsrv.dll.patched c:\windows\system32\termsrv.dll -Force
Set-Acl c:\windows\system32\termsrv.dll $termsrv_dll_acl
Start-Service UmRdpService
Start-Service TermService
Write-Host "Patch was successful!!!" -ForegroundColor Green
Start-Sleep -Seconds 3
Exit
