// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_NtAlpcConnectPort
{
    meta:
        description = "Detects potential abuse of NtAlpcConnectPort via import or string references"
        reference = "Windows API Abuse Atlas: NtAlpcConnectPort"

    strings:
        $NtAlpcConnectPort = "NtAlpcConnectPort" ascii wide

        $token_1 = "AdjustTokenPrivileges" ascii wide
        $token_2 = "DuplicateTokenEx" ascii wide
        $token_3 = "ImpersonateLoggedOnUser" ascii wide
        $token_4 = "OpenProcessToken" ascii wide
        $token_5 = "OpenThreadToken" ascii wide         
        
        $inject_1 = "NtCreateTheadEx" ascii wide
        $inject_2 = "CreateRemoteThread" ascii wide
        $inject_3 = "RtlCreateUserThread" ascii wide
        $inject_4 = "WriteProcessMemory" ascii wide
        $inject_5 = "VirtualAllocEx" ascii wide
        $inject_6 = "QueueUserAPC" ascii wide
        $inject_7 = "SetThreadContext" ascii wide   

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $NtAlpcConnectPort and
        (
            (1 of ($token_*) ) or
            (1 of ($inject_*) )
        )

}
