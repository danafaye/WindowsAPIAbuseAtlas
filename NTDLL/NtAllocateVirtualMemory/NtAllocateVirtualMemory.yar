// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_alloc_write_exec_sequence_strings
{
    meta:
        author = "Windows API Abuse Atlas example"
        description = "Heuristic: binary mentions allocation + protection + thread creation APIs in the same file (noisy but useful for hunting builders)"
    strings:
        $NtAllocateVirtualMemory = "NtAllocateVirtualMemory"
        $api_1 = "NtProtectVirtualMemory"
        $api_2 = "NtWriteVirtualMemory"
        $api_3 = "NtCreateThread"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $NtAllocateVirtualMemory and
        (1 of ($api*))
}
