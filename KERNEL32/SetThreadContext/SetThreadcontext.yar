// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_SetThreadContext_Abuse
{
    meta:
        description = "Detects potential abuse of SetThreadContext with related APIs"
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"
 
    strings:
        $setThreadContext = "SetThreadContext" ascii nocase
        $getThreadContext = "GetThreadContext" ascii nocase
        $suspendThread = "SuspendThread" ascii nocase
        $resumeThread = "ResumeThread" ascii nocase
        $writeProcessMemory = "WriteProcessMemory" ascii nocase
        $virtualAllocEx = "VirtualAllocEx" ascii nocase

    condition:
        uint16(0) == 0x5A4D and // PE file
        filesize < 5MB and
        $setThreadContext and
        (
            $getThreadContext or
            $suspendThread or
            $resumeThread or
            $writeProcessMemory or
            $virtualAllocEx
        )
}
