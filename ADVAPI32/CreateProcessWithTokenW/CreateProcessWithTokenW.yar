// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule CreateProcessWithTokenW_AbusePattern
{
    meta:
        description = "Detects common abuse patterns of CreateProcessWithTokenW in malware"
        author = "Windows API Abuse Atlas"

    strings:
        $api1 = "CreateProcessWithTokenW" ascii
        $api2 = "DuplicateTokenEx" ascii
        $api3 = "OpenProcessToken" ascii
        $api4 = "LogonUser" ascii
        $api5 = "SeAssignPrimaryTokenPrivilege" ascii
        $cmd  = /cmd\.exe|powershell\.exe|wscript\.exe/i

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        all of ($api*) and $cmd
}