// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Potential_NtQueryInformationProcess_Abuse
{
    meta:
        description = "Detects potential abuse of NtQueryInformationProcess via native syscall"
        reference = "Windows API Abuse Atlas"

    strings:
        $api_name1 = "NtQueryInformationProcess" ascii
        $api_name2 = "ZwQueryInformationProcess" ascii
        $info_class_dbgport = { 6A 07 6A 00 68 ?? ?? ?? ?? } // push 0x7 (ProcessDebugPort)
        $info_class_dbgobj  = { 6A 1E 6A 00 68 ?? ?? ?? ?? } // push 0x1e (ProcessDebugObjectHandle)
        $info_class_dbgflag = { 6A 1F 6A 00 68 ?? ?? ?? ?? } // push 0x1f (ProcessDebugFlags)
        $info_class_basic   = { 6A 00 6A 00 68 ?? ?? ?? ?? } // push 0x0 (ProcessBasicInformation)
        $syscall_stub       = { 4C 8B D1 B8 39 00 00 00 0F 05 C3 } // common NtQueryInformationProcess syscall pattern (x64)

    condition:
        1 of ($api_name*) and
        (1 of ($info_class_dbg*) or $info_class_basic or $syscall_stub)
}
