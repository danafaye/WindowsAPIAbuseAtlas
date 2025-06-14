rule Suspicious_NtMapViewOfSection_Usage
{
    meta:
        description = "Detects suspicious usage of NtMapViewOfSection API commonly abused in process injection"
        author = "WindowsAPIAbuseAtlas"
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"
    strings:
        $api_name = "NtMapViewOfSection"
        $related_api_1 = "NtCreateSection"
        $related_api_2 = "NtCreateThreadEx"
        $related_api_3 = "NtUnmapViewOfSection"
        $exec_perm = "PAGE_EXECUTE_READWRITE"

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $api_name and (
            ($related_api_1 and $related_api_3) or
            ($related_api_2 and $related_api_3) or
            $exec_perm
        )
}

rule NtMapViewOfSection_SharedShellcode_GUIInjection
{
    meta:
        description = "Detects memory-resident shellcode injected via shared sections and GUI function pointer abuse (SetWindowLong)"
        author = "WindowsAPIAbuseAtlas"
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"
    strings:
        $api1 = "NtCreateSection" ascii
        $api2 = "NtMapViewOfSection" ascii
        $api3 = "SetWindowLong" ascii
        $api4 = "SendMessage" ascii
        $api5 = "Shell_TrayWnd" ascii
        $api6 = "GetWindowLong" ascii
        $api7 = "PAGE_EXECUTE_READWRITE" ascii wide
        //$gui1 = "WorkerW" ascii
        $shellcode_hint1 = { 60 E8 ?? ?? ?? ?? 5B 81 EB } 
        // PUSHAD; CALL <somewhere>; POP EBX; SUB EBX — classic shellcode setup

        $shellcode_hint2 = { FC E8 ?? ?? ?? ?? 60 89 E5 31 C0 } 
        // Metasploit/Cobalt Strike decoder stub — CLD; CALL; PUSHAD; MOV EBP, ESP; XOR EAX, EAX

        $shellcode_hint3 = { 31 C0 50 68 2E 65 78 65 68 63 61 6C 63 8B C4 } 
        // PUSH ".exe"; PUSH "calc"; typical string-building for loader shellcode

        $shellcode_hint4 = { 6A 30 59 64 8B 01 8B 40 0C 8B 70 1C AD } 
        // PEB/TEB walking — used to resolve kernel32 base address in shellcode

        $shellcode_hint5 = { 68 33 32 00 00 68 77 73 32 5F 54 68 4C 77 26 07 } 
        // PUSH "32"; PUSH "ws2_"; PUSH DWORDs; often part of Win32 shellcode stagers

        //$sec_commit = "SEC_COMMIT" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        3 of ($api*) and 1 of ($shellcode_hint*)
}

