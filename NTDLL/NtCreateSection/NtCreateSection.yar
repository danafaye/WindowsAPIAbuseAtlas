// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

import "pe"

rule NtCreateSection_NtMapViewOfSection_Proximity
{
    meta:
        description = "Detects NtCreateSection and NtMapViewOfSection strings in close proximity, plus any common thread or injection API, in Windows PE files"
        reference = "windows-api-abuse-atlas"
    strings:
        $ntcreate = "NtCreateSection" ascii nocase
        $ntmap    = "NtMapViewOfSection" ascii nocase
        $createremote = "CreateRemoteThread" ascii nocase
        $ntcreatethread = "NtCreateThreadEx" ascii nocase
        $createthread = "CreateThread" ascii nocase
        $rtlcreateuser = "RtlCreateUserThread" ascii nocase
        $queueapc = "QueueUserAPC" ascii nocase
        $setthreadctx = "SetThreadContext" ascii nocase
        $writeproc = "WriteProcessMemory" ascii nocase
        $virtualallocex = "VirtualAllocEx" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            $createremote or $ntcreatethread or $createthread or $rtlcreateuser or $queueapc or $setthreadctx or $writeproc or $virtualallocex
        ) and
        for any i in (1..#ntcreate) : (
            for any j in (1..#ntmap) : (
                ((@ntcreate[i] - @ntmap[j]) >= -64 and (@ntcreate[i] - @ntmap[j]) <= 64)
            )
        )
}

