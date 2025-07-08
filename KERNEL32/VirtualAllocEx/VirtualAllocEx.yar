rule Suspicious_RemoteMemoryAllocation_Use
{
    meta:
        author = "Windows API Abuse Atlas"
        description = "Detects suspicious use of remote memory allocation and injection APIs"

    strings:
        $api1 = "VirtualAllocEx" wide ascii
        $api2 = "WriteProcessMemory" wide ascii
        $api3 = "CreateRemoteThread" wide ascii
        $api4 = "QueueUserAPC" wide ascii
        $api5 = "OpenProcess" wide ascii
        $api6 = "GetProcAddress" wide ascii
        $api7 = "LoadLibraryA" wide ascii
        $api8 = "LoadLibraryW" wide ascii
        $api9 = "NtUnmapViewOfSection" wide ascii
        $api10 = "ZwUnmapViewOfSection" wide ascii

    condition:
        uint16(0) == 0x5A4D and // PE file
        $api1 and $api2 and
        ( $api3 or $api4 ) and
        3 of ($api5, $api6, $api7, $api8, $api9, $api10)
}