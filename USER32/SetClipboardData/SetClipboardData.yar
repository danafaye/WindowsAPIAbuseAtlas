// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_SetClipboardData_Usage
{
    meta:
        description = "Flags binaries that import or reference SetClipboardData and related clipboard APIs, possibly for abuse."
        reference = "Windows API Abuse Atlas - SetClipboardData"

    strings:
        $SetClipboardData = "SetClipboardData" ascii wide
        $a1 = "OpenClipboard" ascii wide
        $a2 = "GetClipboardData" ascii wide
        $a3 = "EmptyClipboard" ascii wide
        $a4 = "AddClipboardFormatListener" ascii wide
        $a5 = "SetClipboardViewer" ascii wide
        $a6 = "ChangeClipboardChain" ascii wide
        $a7 = "GetClipboardSequenceNumber" ascii wide
        $a8 = "IsClipboardFormatAvailable" ascii wide
        $a9 = "RegisterClipboardFormat" ascii wide
        $a10 = "UnregisterClipboardFormat" ascii wide
        $a11 = "GetClipboardData" ascii wide  

        // Optional suspicious context
        $s1 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii wide     // generic BTC address pattern
        $s2 = "powershell" ascii wide
        $s3 = "cmd.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and // Check for MZ header
        filesize < 10MB and
        $SetClipboardData and
        (1 of ($a*)) and
        (1 of ($s*))
}
