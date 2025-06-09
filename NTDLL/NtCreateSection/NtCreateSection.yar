// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule NtCreateSection_NtMapViewOfSection_Proximity
{
    meta:
        description = "Detects potential abuse of NtCreateSection and NtMapViewOfSection in proximity (possible process injection or hollowing)"
        reference = "windows-api-abuse-atlas"
    strings:
        $ntcreate_ascii = "NtCreateSection" ascii nocase
        $ntcreate_wide  = "NtCreateSection" wide nocase
        $ntmap_ascii    = "NtMapViewOfSection" ascii nocase
        $ntmap_wide     = "NtMapViewOfSection" wide nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            for any i in (1..#ntcreate_ascii) : (
                for any j in (1..#ntmap_ascii) : (
                    (@ntcreate_ascii[i] - @ntmap_ascii[j]) >= -128 and (@ntcreate_ascii[i] - @ntmap_ascii[j]) <= 128
                )
            )
            or
            for any i in (1..#ntcreate_wide) : (
                for any j in (1..#ntmap_wide) : (
                    (@ntcreate_wide[i] - @ntmap_wide[j]) >= -128 and (@ntcreate_wide[i] - @ntmap_wide[j]) <= 128
                )
            )
        )
}

rule NtCreateSection_Suspicious_Section_Permissions
{
    meta:
        description = "Detects suspicious use of NtCreateSection or NtMapViewOfSection with executable or RWX section permissions (e.g., PAGE_EXECUTE_READWRITE)"
        reference = "windows-api-abuse-atlas"
    strings:
        $ntcreate_ascii = "NtCreateSection" ascii nocase
        $ntcreate_wide  = "NtCreateSection" wide nocase
        $ntmap_ascii    = "NtMapViewOfSection" ascii nocase
        $ntmap_wide     = "NtMapViewOfSection" wide nocase
        // Common suspicious section permissions (hex for PAGE_EXECUTE_READWRITE and PAGE_EXECUTE_WRITECOPY)
        $perm_exec_rwx  = { 40 00 00 00 }   // PAGE_EXECUTE_READWRITE
        $perm_exec_wc   = { 80 00 00 00 }   // PAGE_EXECUTE_WRITECOPY
        $perm_exec      = { 10 00 00 00 }   // PAGE_EXECUTE
        $perm_exec_rw   = { 20 00 00 00 }   // PAGE_EXECUTE_READ
        $perm_exec_w    = { 08 00 00 00 }   // PAGE_EXECUTE_WRITECOPY (sometimes used)
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (
                any of ($ntcreate_ascii, $ntcreate_wide, $ntmap_ascii, $ntmap_wide)
                and
                1 of ($perm_exec_rwx, $perm_exec_wc, $perm_exec, $perm_exec_rw, $perm_exec_w)
            )
        )
}