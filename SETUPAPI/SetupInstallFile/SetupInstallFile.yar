// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.


rule Suspicious_SetupInstallFile
{
    meta:
        description = "Detects suspicious Suspicious_SetupInstallFile for command execution"
        reference = "Windows API Abuse Atlas: Suspicious_SetupInstallFile"

    strings:
        $SetupInstallFile = "SetupInstallFile" ascii wide

    condition:
        uint16(0) == 0x5A4D and // PE file
        filesize < 10MB and
        $SetupInstallFile
}
