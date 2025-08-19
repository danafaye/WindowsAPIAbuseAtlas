// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule AMSI_AmsiScanString_Patch
{
    meta:
        description = "Detects common AMSI bypass patches on AmsiScanString (e.g., mov eax, 0; ret)"
        author = "Windows API Abuse Atlas"
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"
        date = "2025-08-19"
        threat = "AmsiScanString manipulation / AMSI bypass"

    strings:
        // Classic AMSI bypass patch: mov eax,0; ret (x64: B8 00 00 00 00 C3)
        $patch1 = { B8 00 00 00 00 C3 }

        // Short jump over AMSI call (jmp +6) often used in shellcode patches
        $patch2 = { EB 06 90 90 90 90 }

        // Common PowerShell inline AMSI patch (hex-encoded)
        $patch_ps = "B800000000C3" nocase ascii wide

        // String references to AmsiScanString (suspicious if paired with patching code)
        $amsiStr = "AmsiScanString" ascii wide

    condition:
        (uint16(0) == 0x5A4D and // PE file
        filesize < 10MB) and
        // Look for patches in memory dumps or binaries where AmsiScanString is referenced
        (any of ($patch*) and $amsiStr)
}
