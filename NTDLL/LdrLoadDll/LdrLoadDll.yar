// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_LdrLoadDll_Usage
{
    meta:
        description = "Detects binaries importing or referencing LdrLoadDll, often used to bypass LoadLibrary hooks"
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"
    strings:
        $ldrloaddll = "LdrLoadDll" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        // Look for binaries that explicitly reference the API name
        // and are PE files that import from ntdll.dll
        $ldrloaddll
}