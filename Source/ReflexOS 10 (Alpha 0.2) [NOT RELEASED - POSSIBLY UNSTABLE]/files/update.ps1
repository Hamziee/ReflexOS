#no errors throughout
$ErrorActionPreference = 'silentlycontinue'

Rename-Computer -NewName "ReflexOS" -confirm:$false -Force

Install-Module -Name WindowsOEMinformation -confirm:$false -Force

$oemInfo = @{
    Manufacturer = 'ReflexOS'
    Model = 'ReflexOS 10 (Alpha 0.2)'
    SupportUrl = 'http://reflexos.heo-systems.net/'
}
Set-WindowsOemInformation @oemInfo -confirm:$false -Force

$setwallpapersrc = @"
using System.Runtime.InteropServices;

public class Wallpaper
{
  public const int SetDesktopWallpaper = 20;
  public const int UpdateIniFile = 0x01;
  public const int SendWinIniChange = 0x02;
  [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
  private static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
  public static void SetWallpaper(string path)
  {
    SystemParametersInfo(SetDesktopWallpaper, 0, path, UpdateIniFile | SendWinIniChange);
  }
}
"@
Add-Type -TypeDefinition $setwallpapersrc

[Wallpaper]::SetWallpaper("C:\ReflexOS 10 (Alpha 0.2)\img\ReflexOS Background.png")

# CSP registry path
$RegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
# CSP Registry key names
$LockScreenImagePath = "LockScreenImagePath"
$LockScreenImageStatus = "LockScreenImageStatus"
# CSP Status
$StatusValue = "1"
# Image to use
$LockScreenImageValue = "C:\ReflexOS 10 (Alpha 0.2)\img\ReflexOS Lockscreen.png"  # Change as per your needs
## Check if PersonalizationCSP registry exist and if not create it and add values, or just create the values under it.
if(!(Test-Path $RegKeyPath)){
    New-Item -Path $RegKeyPath -Force | Out-Null
    # Allows for administrators to query the status of the lock screen image.
    New-ItemProperty -Path $RegKeyPath -Name $LockScreenImageStatus -Value $StatusValue -PropertyType DWORD -Force | Out-Null
    # Set the image to use as lock screen background.
    New-ItemProperty -Path $RegKeyPath -Name $LockScreenImagePath -Value $LockScreenImageValue -PropertyType STRING -Force | Out-Null
}
else {
    # Allows for administrators to query the status of the lock screen image.
    New-ItemProperty -Path $RegKeyPath -Name $LockScreenImageStatus -Value $value -PropertyType DWORD -Force | Out-Null
    # Set the image to use as lock screen background.
    New-ItemProperty -Path $RegKeyPath -Name $LockScreenImagePath -Value $LockScreenImageValue -PropertyType STRING -Force | Out-Null
}

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAcrylicBackgroundOnLogon" -Value "1" -PropertyType DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAcrylicBackgroundOnLogon" -Value "1" -PropertyType DWord -Force

Copy-Item "C:\ReflexOS 10 (Alpha 0.2)\icons\User Account Pictures\*" "C:\ProgramData\Microsoft\User Account Pictures\" -force

'sc stop "wsearch" && sc config "wsearch" start=disabled' | cmd

iwr -useb https://christitus.com/win | iex

& 'C:\ReflexOS 10 (Alpha 0.2)\files\BloatyNosy 0.70.149.exe'

