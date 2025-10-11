// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.
import "pe"

rule Suspicious_NtSystemDebugControl_Usage
{
    meta:
        description = "Detects binaries that contain strings and API usage patterns consistent with attempting to resolve/call NtSystemDebugControl or related SYSDBG commands. Intentionally tight to reduce false positives (requires BOTH debug-related strings and dynamic API resolution + privilege indicator)"
        author = "Windows API Abuse Atlas"
        date = "2025-10-11"

    strings:
        // direct target API and commonly abused SYSDBG helpers (ASCII + wide)
        $NtSystemDebugControl = "NtSystemDebugControl" ascii wide

        $support_SysDbgReadVirtual = "SysDbgReadVirtual" ascii wide

        $support_SysDbgWriteVirtual = "SysDbgWriteVirtual" ascii wide

        // physical-memory device path often targeted by low-level tooling
        $support_PhysicalMemory = "PhysicalMemory" ascii wide

        // dynamic resolution + common privilege string — require both to make rule tighter
        $GetProcAddress = "GetProcAddress" ascii wide

        $support_SeDebugPrivilege = "SeDebugPrivilege" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        // Require evidence of dynamic resolution (GetProcAddress) AND at least one
        // debugger/kernel-debug related string. Also require a privilege or physical memory indicator
        ($NtSystemDebugControl and $GetProcAddress)
        and (any of ($support*))

}

rule imports_NtSystemDebugControl {
    meta:
        description = "Detects binaries that import NtSystemDebugControl"
        author = "Windows API Abuse Atlas"
        date = "2025-10-11"
    condition:
        pe.imports("ntdll.dll", "NtSystemDebugControl")
}