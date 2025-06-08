import "pe"

rule EtwEventWrite_Patch_x64
{
    meta:
        description = "Detects x64 patching of EtwEventWrite (xor rax, rax; ret and variants)"
        reference = "windows-api-abuse-atlas"
    strings:
        $xor_ret      = { 48 33 C0 C3 }
        $ret_0x14     = { C2 14 00 }
        $nop_ret      = { 90 90 90 C3 }
        $mov_eax0_ret = { B8 00 00 00 00 C3 }
    condition:
        uint16(0) == 0x5A4D and
        (3 of ($xor_ret, $ret_0x14, $nop_ret, $mov_eax0_ret))
}

rule EtwEventWrite_Patch_x86
{
    meta:
        description = "Detects x86 patching of EtwEventWrite (xor eax, eax; ret and variants)"
        reference = "windows-api-abuse-atlas"
    strings:
        $xor_ret      = { 33 C0 C3 }
        $ret_0x10     = { C2 10 00 }
        $mov_eax0_ret = { B8 00 00 00 00 C3 }
    condition:
        uint16(0) == 0x5A4D and
        (3 of ($xor_ret, $ret_0x10, $mov_eax0_ret))
}

rule EtwEventWrite_Patch_Strings
{
    meta:
        description = "Detects references to EtwEventWrite and related APIs (including stack strings, wide, hex, base64)"
        reference = "windows-api-abuse-atlas"
    strings:
        $etw_ascii      = "EtwEventWrite" ascii nocase
        $etw_wide       = "EtwEventWrite" wide nocase
        // Stack string (split)
        $etw_stack      = "Etw" ascii nocase
        $etw_stack2     = "EventWrite" ascii nocase
        // Hex encoded
        $etw_hex        = { 45 74 77 45 76 65 6E 74 57 72 69 74 65 }
        // Base64 encoded (EtwEventWrite)
        $etw_b64        = { 52 58 4E 76 5A 58 4A 70 5A 57 35 30 }
        // Related APIs
        $getproc        = "GetProcAddress" ascii nocase
        $virtualprotect = "VirtualProtect" ascii nocase
        $writeproc      = "WriteProcessMemory" ascii nocase
        $ntdll_str      = "ntdll.dll" ascii nocase
        // PowerShell/CLR
        $ps_ref         = "Add-Type" ascii nocase
        $clr_ref        = "System.Reflection" ascii nocase
        // Python
        $py_ref         = "ctypes" ascii nocase
        // Go
        $go_ref         = "syscall.NewCallback" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($etw_ascii, $etw_wide, $etw_stack, $etw_stack2, $etw_hex, $etw_b64)) and
        (1 of ($getproc, $virtualprotect, $writeproc, $ntdll_str, $ps_ref, $clr_ref, $py_ref, $go_ref))
}

rule EtwEventWrite_Patch_Base64
{
    meta:
        description = "Detects base64-encoded EtwEventWrite patch shellcode"
        reference = "windows-api-abuse-atlas"
    strings:
        $b64_patch1 = "SDPAww==" // 48 33 C0 C3 (xor rax, rax; ret)
        $b64_patch2 = "whQA"     // C2 14 00 (ret 0x14)
        $b64_patch3 = "kJCQww==" // 90 90 90 C3 (nop; nop; nop; ret)
    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule LockBit_Etw_Patch_OnDisk
{
    meta:
        description = "Detects on-disk LockBit v4 loader that patches EtwEventWrite"
        reference = "windows-api-abuse-atlas"
    strings:
        $xor_ret        = { 48 33 C0 C3 }
        $ret_0x14       = { C2 14 00 }
        $nop_ret        = { 90 90 90 C3 }
        $etw_str        = "EtwEventWrite" ascii nocase
        $getproc        = "GetProcAddress" ascii nocase
        $virtualprotect = "VirtualProtect" ascii nocase
        $writeproc      = "WriteProcessMemory" ascii nocase
        $ntdll_str      = "ntdll.dll" ascii nocase
        $lb_conf        = "LockBit" ascii wide nocase
        $lb_tag         = "LB_CONFIG" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        1 of ($xor_ret, $ret_0x14, $nop_ret) and
        2 of ($etw_str, $getproc, $virtualprotect, $writeproc, $ntdll_str) and
        1 of ($lb_conf, $lb_tag)
}

