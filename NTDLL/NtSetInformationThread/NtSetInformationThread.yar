// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes — not for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

rule NtSetInformationThread_Anti_Debugging
{
    meta:
        description = "Detect potential abuse of NtSetInformationThread for anti-debugging, requiring proximity of function name and 0x11 param or opcode"
        reference = "windows-api-abuse-atlas"
    strings:
        $func_name = "NtSetInformationThread" nocase
        $param_0x11 = { 11 00 00 00 }
        $mov_rdx_11_64 = { 48 C7 C2 11 00 00 00 }
        $mov_edx_11_32 = { BA 11 00 00 00 }
    condition:
        (
            // Proximity: function name and 0x11 param
            for any i in (1..#func_name) : (
                for any j in (1..#param_0x11) : (
                    (@func_name[i] - @param_0x11[j]) >= -64 and (@func_name[i] - @param_0x11[j]) <= 64
                )
            )
            // Proximity: function name and mov rdx, 0x11
            or
            for any i in (1..#func_name) : (
                for any j in (1..#mov_rdx_11_64) : (
                    (@func_name[i] - @mov_rdx_11_64[j]) >= -64 and (@func_name[i] - @mov_rdx_11_64[j]) <= 64
                )
            )
            // Proximity: function name and mov edx, 0x11
            or
            for any i in (1..#func_name) : (
                for any j in (1..#mov_edx_11_32) : (
                    (@func_name[i] - @mov_edx_11_32[j]) >= -64 and (@func_name[i] - @mov_edx_11_32[j]) <= 64
                )
            )
        )
}

rule NtSetInformationThread_Injection_Facilitation
{
    meta:
        description = "Detects likely use of NtSetInformationThread to facilitate injection (e.g., hiding or modifying remote threads)"
        reference = "windows-api-abuse-atlas"
    strings:
        $ntset_ascii = "NtSetInformationThread" ascii nocase
        $ntset_wide  = "NtSetInformationThread" wide nocase
        $threadhide_hex = { 11 00 00 00 }
        $mov_rdx_11_64 = { 48 C7 C2 11 00 00 00 }
        $mov_edx_11_32 = { BA 11 00 00 00 }
        $createremote = "CreateRemoteThread" ascii nocase
        $ntcreatethreadex = "NtCreateThreadEx" ascii nocase
        $virtualallocex = "VirtualAllocEx" ascii nocase
        $writeprocessmemory = "WriteProcessMemory" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (
                // Proximity: function name and 0x11 param
                for any i in (1..#ntset_ascii) : (
                    for any j in (1..#threadhide_hex) : (
                        (@ntset_ascii[i] - @threadhide_hex[j]) >= -64 and (@ntset_ascii[i] - @threadhide_hex[j]) <= 64
                    )
                )
                or
                for any i in (1..#ntset_wide) : (
                    for any j in (1..#threadhide_hex) : (
                        (@ntset_wide[i] - @threadhide_hex[j]) >= -64 and (@ntset_wide[i] - @threadhide_hex[j]) <= 64
                    )
                )
                // Proximity: function name and mov rdx, 0x11
                or
                for any i in (1..#ntset_ascii) : (
                    for any j in (1..#mov_rdx_11_64) : (
                        (@ntset_ascii[i] - @mov_rdx_11_64[j]) >= -64 and (@ntset_ascii[i] - @mov_rdx_11_64[j]) <= 64
                    )
                )
                or
                for any i in (1..#ntset_wide) : (
                    for any j in (1..#mov_rdx_11_64) : (
                        (@ntset_wide[i] - @mov_rdx_11_64[j]) >= -64 and (@ntset_wide[i] - @mov_rdx_11_64[j]) <= 64
                    )
                )
                // Proximity: function name and mov edx, 0x11
                or
                for any i in (1..#ntset_ascii) : (
                    for any j in (1..#mov_edx_11_32) : (
                        (@ntset_ascii[i] - @mov_edx_11_32[j]) >= -64 and (@ntset_ascii[i] - @mov_edx_11_32[j]) <= 64
                    )
                )
                or
                for any i in (1..#ntset_wide) : (
                    for any j in (1..#mov_edx_11_32) : (
                        (@ntset_wide[i] - @mov_edx_11_32[j]) >= -64 and (@ntset_wide[i] - @mov_edx_11_32[j]) <= 64
                    )
                )
            )
            and
            1 of ($createremote, $ntcreatethreadex, $virtualallocex, $writeprocessmemory)
        )
}

rule NtSetInformationThread_Anti_Debugging_Hunt
{
    meta:
        description = "HUNTING: Broadly detect potential abuse of NtSetInformationThread for anti-debugging"
        reference = "windows-api-abuse-atlas"
    strings:
        $func_name_ascii = "NtSetInformationThread" ascii nocase
        $func_name_wide  = "NtSetInformationThread" wide nocase
        $param_0x11 = { 11 00 00 00 }
        $mov_rdx_11_64 = { 48 C7 C2 11 00 00 00 }
        $mov_edx_11_32 = { BA 11 00 00 00 }
    condition:
        (
            for any i in (1..#func_name_ascii) : (
                for any j in (1..#param_0x11) : (
                    (@func_name_ascii[i] - @param_0x11[j]) >= -128 and (@func_name_ascii[i] - @param_0x11[j]) <= 128
                )
            )
            or
            for any i in (1..#func_name_wide) : (
                for any j in (1..#param_0x11) : (
                    (@func_name_wide[i] - @param_0x11[j]) >= -128 and (@func_name_wide[i] - @param_0x11[j]) <= 128
                )
            )
            or
            for any i in (1..#func_name_ascii) : (
                for any j in (1..#mov_rdx_11_64) : (
                    (@func_name_ascii[i] - @mov_rdx_11_64[j]) >= -128 and (@func_name_ascii[i] - @mov_rdx_11_64[j]) <= 128
                )
            )
            or
            for any i in (1..#func_name_wide) : (
                for any j in (1..#mov_rdx_11_64) : (
                    (@func_name_wide[i] - @mov_rdx_11_64[j]) >= -128 and (@func_name_wide[i] - @mov_rdx_11_64[j]) <= 128
                )
            )
            or
            for any i in (1..#func_name_ascii) : (
                for any j in (1..#mov_edx_11_32) : (
                    (@func_name_ascii[i] - @mov_edx_11_32[j]) >= -128 and (@func_name_ascii[i] - @mov_edx_11_32[j]) <= 128
                )
            )
            or
            for any i in (1..#func_name_wide) : (
                for any j in (1..#mov_edx_11_32) : (
                    (@func_name_wide[i] - @mov_edx_11_32[j]) >= -128 and (@func_name_wide[i] - @mov_edx_11_32[j]) <= 128
                )
            )
        )
}

rule NtSetInformationThread_Injection_Facilitation_Hunt
{
    meta:
        description = "HUNTING: Moderately tight detection of likely NtSetInformationThread use for injection"
        reference = "windows-api-abuse-atlas"
    strings:
        $ntset_ascii = "NtSetInformationThread" ascii nocase
        $ntset_wide  = "NtSetInformationThread" wide nocase
        $threadhide_hex = { 11 00 00 00 }
        $mov_rdx_11_64 = { 48 C7 C2 11 00 00 00 }
        $mov_edx_11_32 = { BA 11 00 00 00 }
        $createremote = "CreateRemoteThread" ascii nocase
        $ntcreatethreadex = "NtCreateThreadEx" ascii nocase
        $virtualallocex = "VirtualAllocEx" ascii nocase
        $writeprocessmemory = "WriteProcessMemory" ascii nocase
    condition:
        (
            (
                // Function name and suspicious param/opcode in proximity
                (
                    for any i in (1..#ntset_ascii) : (
                        for any j in (1..#threadhide_hex) : (
                            (@ntset_ascii[i] - @threadhide_hex[j]) >= -64 and (@ntset_ascii[i] - @threadhide_hex[j]) <= 64
                        )
                    )
                    or
                    for any i in (1..#ntset_wide) : (
                        for any j in (1..#threadhide_hex) : (
                            (@ntset_wide[i] - @threadhide_hex[j]) >= -64 and (@ntset_wide[i] - @threadhide_hex[j]) <= 64
                        )
                    )
                    or
                    for any i in (1..#ntset_ascii) : (
                        for any j in (1..#mov_rdx_11_64) : (
                            (@ntset_ascii[i] - @mov_rdx_11_64[j]) >= -64 and (@ntset_ascii[i] - @mov_rdx_11_64[j]) <= 64
                        )
                    )
                    or
                    for any i in (1..#ntset_wide) : (
                        for any j in (1..#mov_rdx_11_64) : (
                            (@ntset_wide[i] - @mov_rdx_11_64[j]) >= -64 and (@ntset_wide[i] - @mov_rdx_11_64[j]) <= 64
                        )
                    )
                    or
                    for any i in (1..#ntset_ascii) : (
                        for any j in (1..#mov_edx_11_32) : (
                            (@ntset_ascii[i] - @mov_edx_11_32[j]) >= -64 and (@ntset_ascii[i] - @mov_edx_11_32[j]) <= 64
                        )
                    )
                    or
                    for any i in (1..#ntset_wide) : (
                        for any j in (1..#mov_edx_11_32) : (
                            (@ntset_wide[i] - @mov_edx_11_32[j]) >= -64 and (@ntset_wide[i] - @mov_edx_11_32[j]) <= 64
                        )
                    )
                )
                and
                1 of ($createremote, $ntcreatethreadex, $virtualallocex, $writeprocessmemory)
            )
        )
}

rule NtSetInformationThread_Early_AntiDebugging_Cluster
{
    meta:
        description = "Detects likely early use of NtSetInformationThread in combination with anti-debugging APIs"
        reference = "windows-api-abuse-atlas"
    strings:
        $ntset = "NtSetInformationThread" ascii nocase
        $isdbg = "IsDebuggerPresent" ascii nocase
        $chkremotedbg = "CheckRemoteDebuggerPresent" ascii nocase
        $getstartup = "GetStartupInfo" ascii nocase
        $outputdebug = "OutputDebugString" ascii nocase
    condition:
        // Look for at least two anti-debugging APIs near NtSetInformationThread
        for any i in (1..#ntset) : (
            (
                for any j in (1..#isdbg) : (
                    (@ntset[i] - @isdbg[j]) >= -1024 and (@ntset[i] - @isdbg[j]) <= 1024
                )
            ) or
            (
                for any j in (1..#chkremotedbg) : (
                    (@ntset[i] - @chkremotedbg[j]) >= -1024 and (@ntset[i] - @chkremotedbg[j]) <= 1024
                )
            ) or
            (
                for any j in (1..#getstartup) : (
                    (@ntset[i] - @getstartup[j]) >= -1024 and (@ntset[i] - @getstartup[j]) <= 1024
                )
            ) or
            (
                for any j in (1..#outputdebug) : (
                    (@ntset[i] - @outputdebug[j]) >= -1024 and (@ntset[i] - @outputdebug[j]) <= 1024
                )
            )
        )
}