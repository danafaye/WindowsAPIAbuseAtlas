// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_ZwUnmapViewOfSection_Usage
{
    meta:
        description = "Detects potential malicious usage of ZwUnmapViewOfSection API"
        reference = "Windows API Abuse Atlas"

    strings:
        $ZwUnmapViewOfSection = "ZwUnmapViewOfSection" ascii wide

        $api_CreateProcess = "CreateProcess" ascii wide
        $api_WriteVirtualMemory = "WriteProcessMemory" ascii wide
        $api_ResumeThread = "ResumeThread" ascii wide
        $api_VirtualAllocEx = "VirtualAllocEx" ascii wide
        $api_MapViewOfSection = "MapViewOfSection" ascii wide
        $api_QueueUserAPC = "QueueUserAPC" ascii wide

    condition:
        uint16(0) == 0x5A4D and // PE file
        filesize < 10MB and
        $ZwUnmapViewOfSection and
        (3 of ($api*))
}
