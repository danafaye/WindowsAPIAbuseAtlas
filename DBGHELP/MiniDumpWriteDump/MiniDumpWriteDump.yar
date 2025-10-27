// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_MiniDumpWriteDump_Usage
{
    meta:
        description = "Detect suspicious use of MiniDumpWriteDump: dynamic dbghelp usage + dumping indicators (lsass, .dmp, GetProcAddress for MiniDumpWriteDump). Requires multiple signals to reduce false positives."
        date = "2025-10-26"
        reference = "Windows API Abuse Atlas — MiniDumpWriteDump"

    strings:
        /* direct symbol names */
        $s_mini            = "MiniDumpWriteDump" ascii wide
        $s_dbghelp         = "dbghelp.dll" ascii wide
        $s_getproc         = "GetProcAddress" ascii wide
        $s_loadlib         = "LoadLibrary" ascii wide


        $s_createfilew     = "CreateFileW" ascii wide
        $s_writefile       = "WriteFile" ascii wide

        /* dump file patterns */
        $s_dotdmp          = ".dmp" ascii wide

        /* target process names commonly dumped (lsass) */
        $s_lsass           = "lsass.exe" ascii wide

        /* optional: flags and common PoC strings */
        $s_minidump_flag   = "MiniDumpWithFullMemory" ascii wide

    condition:
        (uint16(0) == 0x5A4D and // PE file
        filesize < 10MB) and
        (
            ( $s_mini ) or
            ( $s_getproc and $s_dbghelp and $s_loadlib)
        )
        and
        (
            $s_dotdmp or
            $s_lsass or
            $s_createfilew or
            $s_writefile or
            $s_minidump_flag
        )
}
