echo " "
echo " _____    ______   ______   _        ______  __   __   ____     _____ "
echo "|  __ \  |  ____| |  ____| | |      |  ____| \ \ / /  / __ \   / ____|"
echo "| |__) | | |__    | |__    | |      | |__     \ V /  | |  | | | (___  "
echo "|  _  /  |  __|   |  __|   | |      |  __|     > <   | |  | |  \___ \ "
echo "| | \ \  | |____  | |      | |____  | |____   / . \  | |__| |  ____) |"
echo "|_|  \_\ |______| |_|      |______| |______| /_/ \_\  \____/  |_____/ "
echo " "
echo " "
echo "             _      _____  _    _             ___        ___  "
echo "       /\   | |    |  __ \| |  | |   /\      / _ \      |__ \ "
echo "      /  \  | |    | |__) | |__| |  /  \    | | | |        ) |"
echo "     / /\ \ | |    |  ___/|  __  | / /\ \   | | | |       / / "
echo "    / ____ \| |____| |    | |  | |/ ____ \  | |_| |  _   / /_ "
echo "   /_/    \_\______|_|    |_|  |_/_/    \_\  \___/  (_) |____|"
echo " "
echo "Install Script Credits:"
echo "ReflexOS By Hamziee"
echo "Windows10Debloater by Sycnex"
echo "Win10 Initial Setup Script by Disassembler"
echo "The Ultimate Windows Utility by Chris Titus Tech"
echo " "
echo "Install script will start in 10 seconds, close now if you want to cancel."
Start-Sleep 10
echo "Starting..."
Start-Sleep 2
echo " "
echo " "
#This will self elevate the script so with a UAC prompt since this script needs to be run as an Administrator in order to function properly.
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host "You didn't run this script as an Administrator. This script will self elevate to run as an Administrator and continue."
    Start-Sleep 1
    Write-Host "                                               3"
    Start-Sleep 1
    Write-Host "                                               2"
    Start-Sleep 1
    Write-Host "                                               1"
    Start-Sleep 1
    Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

#no errors throughout
$ErrorActionPreference = 'silentlycontinue'

Rename-Computer -NewName "ReflexOS" -Force

Install-Module -Name WindowsOEMinformation

$oemInfo = @{
    Manufacturer = 'ReflexOS'
    Model = 'ReflexOS 10 (Alpha 0.1)'
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

[Wallpaper]::SetWallpaper("C:\ReflexOS 10 (Alpha 0.1)\img\ReflexOS Background.png")

# CSP registry path
$RegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
# CSP Registry key names
$LockScreenImagePath = "LockScreenImagePath"
$LockScreenImageStatus = "LockScreenImageStatus"
# CSP Status
$StatusValue = "1"
# Image to use
$LockScreenImageValue = "C:\ReflexOS 10 (Alpha 0.1)\img\ReflexOS Lockscreen.png"  # Change as per your needs
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

Copy-Item "C:\ReflexOS 10 (Alpha 0.1)\icons\User Account Pictures\*" "C:\ProgramData\Microsoft\User Account Pictures\" -force

'sc stop "wsearch" && sc config "wsearch" start=disabled' | cmd

iwr -useb https://christitus.com/win | iex

Write-Output "Press any key to reboot now"
cmd /c 'pause>nul'
Restart-Computer