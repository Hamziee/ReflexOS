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
echo "BloatyNosy 0.70.149 by builtbybel"
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

& 'C:\ReflexOS 11 (Alpha 0.2)\files\install.ps1'

Restart-Computer
