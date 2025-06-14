rule Possible_DbgUiRemoteBreakin_Abuse {
    meta:
        description = "Detects potential abuse of DbgUiRemoteBreakin for stealthy code injection or anti-debugging"
        author = "Windows API Abuse Atlas"
        
    strings:
        // API strings
        $dbgui_str1 = "DbgUiRemoteBreakin" ascii wide
        $dbgui_str2 = "DbgUi" ascii wide
        
        // Common shellcode patterns
        $shellcode1 = { 60 9C ?? ?? }           // PUSHAD, PUSHFD pattern
        $shellcode2 = { 68 ?? ?? ?? ?? 9C }     // PUSH addr, PUSHFD pattern
        
        // Related API strings often used together
        $rel_api1 = "CreateRemoteThread" ascii wide
        $rel_api2 = "VirtualAllocEx" ascii wide
        $rel_api3 = "WriteProcessMemory" ascii wide
        
        // Anti-debug checks
        $debug1 = { 64 A1 30 00 00 00 }         // MOV EAX, FS:[30h] (PEB access)
        $debug2 = { 80 7? ?? 00 }               // CMP byte ptr [reg+offset], 0

    condition:
        uint16(0) == 0x5A4D and                 // PE file
        (
            // Main detection logic
            ($dbgui_str1 or $dbgui_str2) and
            
            // Additional indicators
            (
                2 of ($shellcode*) or            // Multiple shellcode patterns
                2 of ($rel_api*) or              // Related APIs
                any of ($debug*)                 // Anti-debug routines
            ) and
            
            // File properties
            filesize < 10MB                       // Limit false positives
        )
}