// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_CreateProcessAsUserW_Usage
{
    meta:
        description = "Detects potential abuse of CreateProcessAsUserW in binaries"
        author = "Windows API Abuse Atlas"
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"

    strings:
        $CreateProcessAsUser = "CreateProcessAsUserW" ascii wide
        $api1 = "DuplicateTokenEx" ascii
        $api2 = "LogonUserW" ascii
        $s1 = "SeAssignPrimaryTokenPrivilege" ascii
        $s2 = "SeIncreaseQuotaPrivilege" ascii

    condition:
        uint16(0) == 0x5A4D and
        $CreateProcessAsUser and
        filesize < 10MB and
        ($api1 or $api2) and 
        ($s1 or $s2)
}
