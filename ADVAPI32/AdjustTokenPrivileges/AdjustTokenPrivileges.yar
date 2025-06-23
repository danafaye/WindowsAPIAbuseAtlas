// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Detect_AdjustTokenPrivileges_Usage
{
    meta:
        description = "Detects common abuse patterns of CreateProcessWithTokenW in malware"
        author = "Windows API Abuse Atlas"

    strings:
        $func = "AdjustTokenPrivileges"
        $lookup = "LookupPrivilegeValueW"
        $open_process = "OpenProcessToken"
        $sedebug = "SeDebugPrivilege"

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        all of ($func, $lookup) and
        any of ($open_process, $sedebug)
}