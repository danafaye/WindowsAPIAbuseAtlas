// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_LoadLibrary_Usage
{
    meta:
        description = "Detects potentially malicious use of LoadLibrary (dynamic resolution, injection patterns)"
        author = "Windows API Abuse Atlas"
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"
        threat = "Potential code injection / reflective loading / DLL sideloading"

    strings:
        // Direct API names
        $LoadLibrary = "LoadLibrary" ascii wide
        $GetProcAddress  = "GetProcAddress" ascii wide
        $CreateRemoteThread = "CreateRemoteThread" ascii wide
        $WriteProcessMemory = "WriteProcessMemory" ascii wide
        $VirtualAlloc  = "VirtualAlloc" ascii wide
        $VirtualProtect = "VirtualProtect" ascii wide

        // Obfuscated / split LoadLibrary strings often seen in malware
        $obf1 = "Loa" ascii
        $obf2 = "dLib" ascii
        $obf3 = "rary" ascii

    condition:
        uint16(0) == 0x5A4D and  // PE header
        filesize < 2MB and
        (
            // Suspicious combos: LoadLibrary + GetProcAddress (dynamic imports)
            ($LoadLibrary and $GetProcAddress) or

            // Classic injection chain: LoadLibrary + CreateRemoteThread + WriteProcessMemory
            ($LoadLibrary and $CreateRemoteThread and $WriteProcessMemory) or

            // Memory allocation + LoadLibrary together (often reflective loaders)
            ($LoadLibrary and $VirtualAlloc and $VirtualProtect) or

            // Obfuscated references like "Loa" + "dLib" + "rary"
            all of ($obf*)
        )
}
