// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

import "pe"

rule UpdateProcThreadAttribute_ParentSpoofing
{
    meta:
        description = "Detects UpdateProcThreadAttribute used with parent process spoofing or process creation APIs"
        reference = "windows-api-abuse-atlas"
    strings:
        $update = "UpdateProcThreadAttribute" ascii nocase
        $parent = "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS" ascii nocase
        $create = "CreateProcess" ascii nocase
        $createinternal = "CreateProcessInternalW" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $update and
        ($parent or $create or $createinternal)
}

rule UpdateProcThreadAttribute_InjectionChain
{
    meta:
        description = "Detects UpdateProcThreadAttribute used with process injection APIs"
        reference = "windows-api-abuse-atlas"
    strings:
        $update = "UpdateProcThreadAttribute" ascii nocase
        $virtualalloc = "VirtualAllocEx" ascii nocase
        $write = "WriteProcessMemory" ascii nocase
        $createremote = "CreateRemoteThread" ascii nocase
        $queueapc = "NtQueueApcThread" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $update and
        $virtualalloc and
        ($write or $createremote or $queueapc)
}