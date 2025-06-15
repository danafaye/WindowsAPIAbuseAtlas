rule Static_ProcessInjection_Pattern
{
    meta:
        description = "Detects classic process injection chains using NtWriteVirtualMemory"
        author = "Dana Behling"
        version = "2.0"
        date = "2025-06-15"
        reference = "Windows API Abuse Atlas"

    strings:
        $open   = "OpenProcess" ascii wide
        $alloc  = "VirtualAllocEx" ascii wide
        $write1 = "NtWriteVirtualMemory" ascii wide
        $write2 = "WriteProcessMemory" ascii wide
        $thread1 = "CreateRemoteThread" ascii wide
        $thread2 = "NtCreateThreadEx" ascii wide
        $notepad = "notepad.exe" ascii wide
        $explorer = "explorer.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and // PE file
        filesize < 10MB and
        2 of ($write*) and
        1 of ($thread*) and
        all of ($open, $alloc) and
        ($notepad or $explorer)
}
