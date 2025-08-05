// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_OpenDesktop_Abuse
{
    meta:
        description = "Detects potential abuse of OpenDesktop API, especially with Winlogon spoofing"
        reference = "Windows API Abuse Atlas - OpenDesktop"

    strings:
        $opendesktop = "OpenDesktopA" ascii wide
        $opendesktopW = "OpenDesktopW" ascii wide
        $switchdesktop = "SwitchDesktop" ascii wide
        $setthreaddesktop = "SetThreadDesktop" ascii wide
        $creatdesktop = "CreateDesktopA" ascii wide
        $winlogon_str = "Winlogon" ascii wide
        $disconnect_str = "Disconnect" ascii wide
        $securedesktop_str = "Secure" ascii wide

    condition:
         uint16(0) == 0x5A4D and // Check for MZ header
        filesize < 10MB and
        2 of ($opendesktop, $opendesktopW, $switchdesktop, $setthreaddesktop, $creatdesktop) and
        1 of ($winlogon_str, $disconnect_str, $securedesktop_str)
}
