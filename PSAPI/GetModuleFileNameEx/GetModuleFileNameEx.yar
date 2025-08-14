// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

import "pe"

rule Suspicious_GetModuleFileNameEx_Usage
{
    meta:
        description = "Detects potential malicious use of GetModuleFileNameEx API in binaries"
        note = "Hunting rule - expect false positives"
    strings:
        $GetModuleFileNameEx = "GetModuleFileNameEx" ascii wide
        $EnumProcesses = "EnumProcesses" ascii wide
        $OpenProcess = "OpenProcess" ascii wide

    condition:
        uint16(0) == 0x5A4D and // PE file
        filesize < 10MB and
        pe.imports("psapi.dll") > 0 and
        $GetModuleFileNameEx and
        $EnumProcesses and
        $OpenProcess
}