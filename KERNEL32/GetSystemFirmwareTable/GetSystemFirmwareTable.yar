// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.
import "pe"

rule Suspicious_GetSystemFirmwareTable_Usage
{
    meta:
        author = "Windows API Abuse Atlas"
        description = "Detects potential malicious calls to GetSystemFirmwareTable in Windows binaries"
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"

    strings:
        // API name
        $GetSystemFirmwareTable = "GetSystemFirmwareTable" ascii wide
    
    condition:
        uint16(0) == 0x5A4D and  // PE header
        filesize < 2MB and
        (pe.imports("GetSystemFirmwareTable") or 
        $GetSystemFirmwareTable)
}