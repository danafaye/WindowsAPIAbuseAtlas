rule Possible_EtwTraceEvent_Abuse
{
    meta:
        description = "Detects suspicious usage or resolution of EtwTraceEvent, often abused for ETW spoofing or evasion"
        author = "Windows API Abuse Atlas"
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"

    strings:
        $api_name = "EtwTraceEvent" wide ascii
        $api_name_nt = "NtTraceEvent" wide ascii
        $ntdll = "ntdll.dll" wide ascii
        $getproc = "GetProcAddress" wide ascii
        $loadlib = "LoadLibraryA" wide ascii
        $traceevent_sig = { 4C 8B DC 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 8B DA } // common EtwTraceEvent prologue in ntdll (x64)

    condition:
        // Catch binaries that import or resolve NtTraceEvent or EtwTraceEvent manually
        (uint16(0) == 0x5A4D and
            (1 of ($api_name, $api_name_nt, $traceevent_sig) and
             1 of ($getproc, $loadlib, $ntdll)))
}
