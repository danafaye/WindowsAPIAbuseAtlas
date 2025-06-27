// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_SetWindowsHookEx_Usage
{
    meta:
        description = "Detects binaries that import or reference SetWindowsHookEx which may indicate keylogging, injection, or UI tampering behavior"
        reference = "Windows API Abuse Atlas"

    strings:
        $func = "SetWindowsHookEx" ascii wide
        $dll = "user32.dll" ascii

        // Common hook constants as dword (little-endian)
        $wh_keyboard_ll = { 0D 00 00 00 }  // 13
        $wh_mouse_ll    = { 0E 00 00 00 }  // 14
        $wh_cbt         = { 05 00 00 00 }  // 5
        $wh_callwndproc = { 04 00 00 00 }  // 4
    condition:
        (uint16(0) == 0x5A4D) and // MZ header check
        filesize < 10MB and // Reasonable file size limit
        $dll and
        (
            $func and
            (
                $wh_keyboard_ll in ( @func - 100 .. @func + 100 ) or
                $wh_mouse_ll    in ( @func - 100 .. @func + 100 ) or
                $wh_cbt         in ( @func - 100 .. @func + 100 ) or
                $wh_callwndproc in ( @func - 100 .. @func + 100 )
            )
        )
}