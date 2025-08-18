// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_DuplicateTokenEx_Usage
{
    meta:
        author = "Windows API Abuse Atlas"
        description = "Detects binaries that reference DuplicateTokenEx for potential token theft/privilege escalation"
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"
    
    strings:
        $DuplicateTokenEx = "DuplicateTokenEx" ascii wide

        // common related APIs often paired with DuplicateTokenEx
        $api_1 = "CreateProcessWithTokenW" ascii wide
        $api_2 = "CreateProcessAsUserW" ascii wide
        $api_3 = "ImpersonateLoggedOnUser" ascii wide
    
    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        // Match if DuplicateTokenEx is present, especially with its "friends"
        $DuplicateTokenEx and
        (any of ($api_*) )
}
