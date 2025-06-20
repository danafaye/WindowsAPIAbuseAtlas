// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

/**
rule WriteProfileString_Abuse_Processes
{
    meta:
        description = "Detects suspicious WriteProfileString API usage by monitoring known abusing processes"
        reference = "Windows API Abuse Atlas - WriteProfileString"

    strings:
        $WriteProfileString = "WriteProfileString" ascii wide
        $powershell = "powershell.exe" ascii wide nocase
        $wscript = "wscript.exe" ascii wide nocase
        $rundll32 = "rundll32.exe" ascii wide nocase
        $cscript = "cscript.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and // PE file
        filesize < 10MB and
        $WriteProfileString and
        any of ($powershell, $wscript, $rundll32, $cscript)
}
**/


rule WriteProfileString_API_Call
{
    meta:
        description = "Detects potential embedded WriteProfileString API calls in binary code"
        reference = "Windows API Abuse Atlas - WriteProfileString"

    strings:
        $apiA = "WriteProfileStringA"
        $apiW = "WriteProfileStringW"

        // Suspicious section or key names
        $sect1 = "MicrosoftUpdate"
        $sect2 = "Loader"
        $sect3 = "Config"
        $sect4 = "Settings"
        $sect5 = "RunKey"
        $sect6 = "Startup"

        // Encoded or obfuscated-looking data
        $base64 = /[A-Za-z0-9+\/=]{20,}/ nocase
        $hex = /[0-9A-Fa-f]{20,}/

        // Unusual file paths
        $tmp_path = "\\\\?\\C:\\\\Users\\\\.*\\\\AppData\\\\Local\\\\Temp\\\\.*\\.ini" nocase
        $hardcoded_ini = /[A-Z]:\\\\[^\\]+\\\\[^\\]+\.ini/ nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (1 of ($api*) and 2 of ($sect*,$base64,$hex,$tmp_path,$hardcoded_ini))

}
