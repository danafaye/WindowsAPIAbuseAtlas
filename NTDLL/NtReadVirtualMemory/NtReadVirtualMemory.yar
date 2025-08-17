// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.
import "pe"

rule Suspicious_NtReadVirtualMemory_Import
{
  meta:
    description = "Binary imports ntdll!NtReadVirtualMemory (often paired with injection/dumping)"
    author = "Windows API Abuse Atlas"
  strings:
    $NtReadVirtualMemory = "NtReadVirtualMemory" ascii wide
    $GetProcAddress = "GetProcAddress" ascii wide
    $LoadLibrary = "LoadLibrary" ascii wide
  condition:
    uint16(0) == 0x5A4D and
    filesize < 10MB and
    all of them
}

rule Direct_Syscall_Stub_ReadVirtualMemory_Like
{
  meta:
    description = "Heuristic syscall stub often used to invoke NT APIs directly"
    author = "Windows API Abuse Atlas"
    note = "General syscall stub; not specific to NtReadVirtualMemory. High FP risk."
  strings:
    $prolog = { 49 89 CA B8 ?? ?? 00 00 0F 05 C3 }
  condition:
    uint16(0) == 0x5A4D and
    filesize < 10MB and
    $prolog
}