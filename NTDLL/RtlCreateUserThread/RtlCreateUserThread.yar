// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_RtlCreateUserThread_Usage
{
    meta:
        author = "Windows API Abuse Atlas"
        description = "Detects dynamic resolution and usage patterns of RtlCreateUserThread"
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"

    strings:
        $load_ntdll          = "LoadLibraryA" ascii wide
        $load_ntdllw         = "LoadLibraryW" ascii wide
        $get_proc_address    = "GetProcAddress" ascii wide
        $ldr_get_proc_addr   = "LdrGetProcedureAddress" ascii wide
        $rtl_create_thread   = "RtlCreateUserThread" ascii wide
        $ntdll_dll           = "ntdll.dll" ascii wide

        // Common function hashes or export parsing strings (example hashes as hex strings)
        $hash_func_call      = { 8B 0D ?? ?? ?? ?? 33 C0 39 0D ?? ?? ?? ?? } // sample pattern for hash calculation (example)
        $export_table_walk   = "AddressOfNames" ascii wide
        $export_table_walk2  = "NameOrdinals" ascii wide
        $export_table_walk3  = "AddressOfFunctions" ascii wide

    condition:
        (
            (
                ($load_ntdll or $load_ntdllw) and 
                ($get_proc_address or $ldr_get_proc_addr)
            ) and 
            $rtl_create_thread and 
            $ntdll_dll
        )
        or
        (
            $hash_func_call and
            (
                $export_table_walk or
                $export_table_walk2 or
                $export_table_walk3
            )
        )
}
