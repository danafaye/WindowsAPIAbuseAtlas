// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule NtOpenProcessToken_Suspicious
{
    meta:
        author = "Windows API Abuse Atlas"
        description = "Detects references to NtOpenProcessToken + sibling APIs (DuplicateTokenEx, OpenProcess, CreateProcessWithTokenW, etc.) — hunting rule, not high-fidelity prevention."
 
    strings:
        $NtOpenProcessToken = "NtOpenProcessToken" ascii wide
        $api_DuplicateToken = "DuplicateToken" ascii wide
        $api_OpenProcess = "OpenProcess" ascii wide
        $api_NtDuplicateObject = "NtDuplicateObject" ascii wide
        $api_CreateProcessWithTokenW = "CreateProcessWithTokenW" ascii wide
        $api_SetThreadToken = "SetThreadToken" ascii wide
        $api_ImpersonateLoggedOnUser = "ImpersonateLoggedOnUser" ascii wide
        $api_SeDebugPrivilege = "SeDebugPrivilege" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $NtOpenProcessToken and
        2 of ($api_*)
}