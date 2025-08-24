// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_RegEnumKeyEx_Usage
{
    meta:
        author = "Windows API Abuse Atlas"
        description = "Detects suspicious references to RegEnumKeyEx, often abused for registry reconnaissance"
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"

    strings:
        $RegEnumKey = "RegEnumKey" ascii wide

        $api_1 = "RegOpenKeyEx" ascii wide
        $api_2 = "RegQueryValueEx" ascii wide
        $api_3 = "RegSetValueEx" ascii wide
        $api_4 = "RegCreateKeyEx" ascii wide
        $api_5 = "RegDeleteKey" ascii wide
        $api_6 = "RegDeleteValue" ascii wide
        $api_7 = "RegCloseKey" ascii wide   

    condition:
        uint16(0) == 0x5A4D and // MZ header
        $RegEnumKey and
        (2 of ($api_*))  // At least one other registry API
}