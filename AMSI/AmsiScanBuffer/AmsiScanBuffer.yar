// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_AmsiScanBuffer_Activity
{
    meta:
        author = "Windows API Abuse Atlas"
        description = "Detects suspicious dynamic resolution or tampering with AmsiScanBuffer and related AMSI functions"
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"

    strings:
        // AMSI related API names and DLL
        $amsi_scan_buffer      = "AmsiScanBuffer" ascii wide
        $amsi_scan_string      = "AmsiScanString" ascii wide
        $amsi_initialize       = "AmsiInitialize" ascii wide
        $amsi_open_session     = "AmsiOpenSession" ascii wide
        $amsi_close_session    = "AmsiCloseSession" ascii wide
        $amsi_dll              = "amsi.dll" ascii wide

        // Common APIs used to patch/hook AMSI in memory
        $virtual_protect       = "VirtualProtect" ascii wide
        $nt_protect_virtual    = "NtProtectVirtualMemory" ascii wide

        // Strings related to dynamic API resolution often used by malware
        $loadlibrary           = "LoadLibraryA" ascii wide
        $getprocaddress        = "GetProcAddress" ascii wide

    condition:
        uint16(0) == 0x5A4D and // PE file
        (
            // Dynamic resolution of AMSI APIs
            ( $loadlibrary and $getprocaddress and (
                $amsi_scan_buffer or $amsi_scan_string or $amsi_initialize or $amsi_open_session or $amsi_close_session
            ))
            or
            // Presence of amsi.dll and memory protection APIs indicating possible patching
            ( $amsi_dll and ( $virtual_protect or $nt_protect_virtual ))
        )
}
