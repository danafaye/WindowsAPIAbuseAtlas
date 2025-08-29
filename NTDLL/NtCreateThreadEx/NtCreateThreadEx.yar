// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.


rule NtCreateThreadEx_Suspicious_Combo
{
    meta:
        description = "Detects binaries using NtCreateThreadEx with other suspicious APIs"
        author = "WindowsAPIAbuseAtlas"
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"
    strings:
        $NtCreateThreadEx = "NtCreateThreadEx" ascii wide
        $api1 = "NtAllocateVirtualMemory" ascii wide
        $api2 = "NtProtectVirtualMemory" ascii wide
        $api3 = "NtWriteVirtualMemory" ascii wide
        $api4 = "NtQueueApcThread" ascii wide
        $api5 = "NtResumeThread" ascii wide
        $api6 = "NtOpenProcess" ascii wide
        $api7 = "NtOpenThread" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $NtCreateThreadEx and 
        (2 of ($api*))
}