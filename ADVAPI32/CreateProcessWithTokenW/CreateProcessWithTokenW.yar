// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.


rule Suspicious_CreateProcessWithTokenW_Usage
{
    meta:
        author = "Windows API Abuse Atlas"
        description = "Detects use of CreateProcessWithTokenW with suspicious token manipulation patterns"
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"

    strings:
        $api1 = "CreateProcessWithToken" ascii wide
        $api2 = "DuplicateTokenEx" ascii wide
        $api3 = "OpenProcessToken" ascii wide
        $api4 = "OpenProcess" ascii wide
        $api5 = "LookupPrivilegeValue" ascii wide
        $lolbin1 = "cmd.exe" ascii wide
        $lolbin2 = "powershell.exe" ascii wide
        $lolbin3 = "rundll32.exe" ascii wide

    condition:
        all of ($api*) and 1 of ($lolbin*) and filesize < 5MB
}
