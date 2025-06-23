// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.


rule NtProtectVirtualMemory_ProcessInjection
{
    meta:
        description = "Detects use of NtProtectVirtualMemory for process injection"
        author = "Windows API Abuse Atlas"
    strings:
        $a = "NtProtectVirtualMemory" ascii
        $b = "VirtualAllocEx" ascii
        $c = "WriteProcessMemory" ascii
        $d = "CreateRemoteThread" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and
        all of them
        //2 of ($a, $b, $c, $d)
}

rule NtProtectVirtualMemory_ServiceInjection
{
    meta:
        description = "Detects use of NtProtectVirtualMemory for service injection"
        author = "Windows API Abuse Atlas"
    strings:
        $a = "NtProtectVirtualMemory" ascii
        $b = "OpenSCManager" ascii
        $c = "OpenService" ascii
        $d = "QueryServiceStatusEx" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and
        all of them
        //$a and 1 of ($b, $c, $d)
}

rule NtProtectVirtualMemory_Unhooking
{
    meta:
        description = "Detects use of NtProtectVirtualMemory for user-mode unhooking"
        author = "Windows API Abuse Atlas"
    strings:
        $a = "NtProtectVirtualMemory" ascii
        $b = "GetModuleHandle" ascii
        $c = "ntdll.dll" ascii
        $d = "memcpy" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and
        all of them
        //$a and 1 of ($b, $c, $d)
}

rule NtProtectVirtualMemory_AntiDebugging
{
    meta:
        description = "Detects use of NtProtectVirtualMemory for anti-debugging"
        author = "Windows API Abuse Atlas"
    strings:
        $a = "NtProtectVirtualMemory" ascii
        $b = "NtQueryInformationProcess" ascii
        $c = "CheckRemoteDebuggerPresent" ascii
        $d = "DbgBreakPoint" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and
        all of them
        //$a and 1 of ($b, $c, $d)
}

rule NtProtectVirtualMemory_EnclaveAbuse
{
    meta:
        description = "Detects NtProtectVirtualMemory usage in VBS/IUM enclave manipulation"
        author = "Windows API Abuse Atlas"
    strings:
        $a = "NtProtectVirtualMemory" ascii
        $b = "NtCreateUserProcess" ascii
        $c = "IsolatedUserMode" ascii nocase
        $d = "VirtualizationBasedSecurity" ascii nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and
        all of them
        //$a and 1 of ($b, $c, $d)
}

rule ProcessInjection_Explorer_Shellcode
{
    meta:
        description = "Detects process injection targeting explorer.exe with shellcode and key APIs"
        author = "Windows API Abuse Atlas"

    strings:
        // Key APIs used in process injection
        $api1 = "NtProtectVirtualMemory" ascii fullword
        $api2 = "NtWriteVirtualMemory" ascii fullword
        $api3 = "NtAllocateVirtualMemory" ascii fullword
        $api4 = "NtCreateThreadEx" ascii fullword
        $api5 = "OpenProcess" ascii fullword

        // Common target process for injection
        $target1 = "explorer.exe" ascii nocase fullword
        $target2 = "scvhost.exe" ascii nocase fullword

        // Typical shellcode stub pattern (common x64 prologue bytes)
        $shellcode = { FC 48 83 E4 F0 E8 }

    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and
        all of ($api*) and
        any of ($target*) and
        $shellcode
}
