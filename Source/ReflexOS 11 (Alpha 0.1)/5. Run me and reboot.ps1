# Ask for elevated permissions if required
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

New-Itemproperty -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name 'VisualFXSetting' -value '3'
Set-Itemproperty -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name 'VisualFXSetting' -value '3'
Rename-Computer -NewName "ReflexOS" -Force

Install-Module -Name WindowsOEMinformation

$oemInfo = @{
    Manufacturer = 'ReflexOS'
    Model = 'ReflexOS 11 (Alpha 0.1)'
    SupportUrl = 'http://reflexos.heo-systems.net/'
}
Set-WindowsOemInformation @oemInfo

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

[Wallpaper]::SetWallpaper("C:\ReflexOS 11 (Alpha 0.1)\img\ReflexOS Background.png")

# CSP registry path
$RegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
# CSP Registry key names
$LockScreenImagePath = "LockScreenImagePath"
$LockScreenImageStatus = "LockScreenImageStatus"
# CSP Status
$StatusValue = "1"
# Image to use
$LockScreenImageValue = "C:\ReflexOS 11 (Alpha 0.1)\img\ReflexOS Lockscreen.png"  # Change as per your needs
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

Copy-Item "C:\ReflexOS 11 (Alpha 0.1)\icons\User Account Pictures\*" "C:\ProgramData\Microsoft\User Account Pictures\" -force

echo "REBOOT NOW"