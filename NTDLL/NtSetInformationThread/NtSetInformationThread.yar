rule NtSetInformationThread_Abuse
{
    meta:
        description = "Detect potential abuse of NtSetInformationThread for anti-debugging or injection"
        reference = "windows-api-abuse-atlas"

    strings:
        // The function name or syscall number patterns
        $func_name = "NtSetInformationThread" nocase
        // Suspicious parameter value for ThreadHideFromDebugger (0x11)
        $param_0x11 = { 11 00 00 00 }

        // Opcodes pattern: mov rdx, 0x11 or mov edx, 0x11 (setting ThreadHideFromDebugger)
        $mov_rdx_11_64 = { 48 C7 C2 11 00 00 00 }
        $mov_edx_11_32 = { BA 11 00 00 00 }

    condition:
        // Detect the function name in imports or strings, AND
        // suspicious constant 0x11 (ThreadHideFromDebugger) or related opcode pattern present
        $func_name and (
            $param_0x11 or
            $mov_rdx_11_64 or
            $mov_edx_11_32
        )
}
