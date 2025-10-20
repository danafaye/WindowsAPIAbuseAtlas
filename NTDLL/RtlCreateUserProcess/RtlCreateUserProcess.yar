// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

import "pe"

rule RTLCreateUserProcess_LowFalsePositive
{
    meta:
        author = "Windows API Abuse Atlas"
        description = "Low-FP rule for binaries that import RtlCreateUserProcess or a tight combo of native process-creation helpers from ntdll.dll"

    condition:
        uint16(0) == 0x5A4D and  
        not (pe.characteristics & 0x2000) == 0 and   /* prefer executables; DLLs often legitimately export/import many native helpers */
        (
            /* direct import of the explicit native API (strongest single-signal) */
            pe.imports("ntdll.dll", "RtlCreateUserProcess")
            or
            /* composite signal: both a process-parameters helper and a section-creation helper imported from ntdll */
            (
                pe.imports("ntdll.dll", "RtlCreateProcessParametersEx") and
                pe.imports("ntdll.dll", "NtCreateSection")
            )
        )                   
}

rule RTLCreateUserProcess_ResolverPattern
{
    meta:
        author = "Windows API Abuse Atlas"
        description = "Detects potential dynamic resolution of RtlCreateUserProcess: resolver imports + embedded symbol or ntdll reference"
        date = "2025-10-19"

    strings:
        $RtlCreateUserProcess = "RtlCreateUserProcess" ascii
        $s_ntdll = "ntdll.dll" ascii
        $s_getproc = "GetProcAddress" ascii
        $s_loadlib = "LoadLibraryA" ascii
        $s_loadlibw = "LoadLibraryW" ascii
        $s_ldrget = "LdrGetProcedureAddress" ascii

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        (
            /* one of the resolver imports exists */
            pe.imports("kernel32.dll", "GetProcAddress") or
            pe.imports("kernel32.dll", "LoadLibraryA") or
            pe.imports("kernel32.dll", "LoadLibraryW") or
            pe.imports("ntdll.dll", "LdrGetProcedureAddress")
        ) and
        $RtlCreateUserProcess and
        (any of ($s*))
}