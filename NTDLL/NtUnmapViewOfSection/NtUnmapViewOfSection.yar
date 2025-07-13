// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.


rule Suspicious_NtUnmapViewOfSection_Usage
{
    meta:
        author = "Windows API Abuse Atlas"
        description = "Flags binaries referencing NtUnmapViewOfSection with characteristics suggesting process hollowing or injection"
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"

    strings:
        $api = "NtUnmapViewOfSection" ascii
        $create_section = "NtCreateSection" ascii
        $map_section = "NtMapViewOfSection" ascii
        $write_mem = "NtWriteVirtualMemory" ascii
        $resume_thread = "NtResumeThread" ascii
        $create_process = "CreateProcessW" ascii

    condition:
        uint16(0) == 0x5A4D and                    // Check for MZ header
        filesize < 5MB and                         // Filter out large installers
        $api and                                   // Must reference NtUnmapViewOfSection
        (1 of ($create_section, $map_section, $write_mem, $resume_thread, $create_process))
}
