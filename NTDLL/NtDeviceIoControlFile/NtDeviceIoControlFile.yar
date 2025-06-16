// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.


rule NtDeviceIoControlFile_Suspicious_Combo
{
    meta:
        description = "Detects binaries using NtDeviceIoControlFile with other driver-related APIs"
        author = "WindowsAPIAbuseAtlas"
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"
    strings:
        $ntdev = "NtDeviceIoControlFile" ascii wide
        $ntopen = "NtOpenFile" ascii wide
        $ntload = "NtLoadDriver" ascii wide
        $ntunload = "NtUnloadDriver" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        $ntdev and (1 of ($ntopen, $ntload, $ntunload))
}

rule NtDeviceIoControlFile_KnownBad_IOCTL
{
    meta:
        description = "Detects use of NtDeviceIoControlFile with known suspicious IOCTL codes"
        author = "WindowsAPIAbuseAtlas"
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"
    strings:
        $ntdev = "NtDeviceIoControlFile" ascii wide
        // RTCore64.sys
        $ioctl1 = { 0C 24 22 00 }
        $ioctl2 = { 08 24 22 00 }
        // GDRV.sys
        $ioctl3 = { 08 28 50 C3 }
        $ioctl4 = { 0C 28 50 C3 }
        // AsrDrv104.sys
        $ioctl5 = { 80 25 40 9C }
        $ioctl6 = { 84 25 40 9C }
        // KProcessHacker.sys
        $ioctl7 = { 0B 20 22 00 }
        $ioctl8 = { 0F 20 22 00 }
    condition:
        uint16(0) == 0x5A4D and
        $ntdev and any of ($ioctl*)
}

rule NtDeviceIoControlFile_SuspiciousStrings
{
    meta:
        description = "Detects suspicious driver/device names with NtDeviceIoControlFile"
        author = "WindowsAPIAbuseAtlas"
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"
    strings:
        $ntdev = "NtDeviceIoControlFile" ascii wide
        $drv1 = "\\\\.\\PhysicalDrive" ascii wide
        $drv2 = "\\\\.\\EvilDrv" ascii wide
        $drv3 = "\\\\.\\KProcessHacker" ascii wide
        $drv4 = "\\\\.\\GLOBALROOT\\Device\\Harddisk" ascii wide
        $drv5 = "\\\\.\\AsrDrv104" ascii wide
        $drv6 = "\\\\.\\GIO" ascii wide
        $drv7 = "\\\\.\\RTCore64" ascii wide
        $drv8 = "\\\\.\\DBUtil_2_3" ascii wide
        $drv9 = "\\\\.\\Sys" ascii wide
        $drv10 = "\\\\.\\WinRing0_1_2_0" ascii wide
        $drv11 = "\\\\.\\NvFlash" ascii wide
        $drv12 = "\\\\.\\MsIo" ascii wide
        $drv13 = "\\\\.\\PROCEXP152" ascii wide
        $drv14 = "\\\\.\\TaskExplorer" ascii wide
        $drv15 = "\\\\.\\VBoxDrv" ascii wide
        $drv16 = "\\\\.\\HackSysExtremeVulnerableDriver" ascii wide
        $drv17 = "\\\\.\\afd" ascii wide
        $drv18 = "\\\\.\\pipe\\" ascii wide
        $drv19 = "\\\\.\\SbieDrv" ascii wide
        $drv20 = "\\\\.\\Global\\EPMMap" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        $ntdev and any of ($drv*)
}