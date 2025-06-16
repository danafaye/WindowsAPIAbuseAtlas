// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

import "pe"

rule NtQueueApcThread
{
    meta:
        description = "Detects APC injection: NtQueueApcThread + ResumeThread + memory allocation/writing"
        reference = "windows-api-abuse-atlas"
    strings:
        $ntqueueapc = "NtQueueApcThread" ascii nocase
        $resumethread = "ResumeThread" ascii nocase
        $virtualalloc = "VirtualAllocEx" ascii nocase
        $writeproc = "WriteProcessMemory" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $ntqueueapc and
        $resumethread and
        ($virtualalloc or $writeproc)
}

rule NtQueueApcThread_AtomBombing
{
    meta:
        description = "Detects AtomBombing: NtQueueApcThread + atom table APIs + (optional) memory writing"
        reference = "windows-api-abuse-atlas"
    strings:
        $ntqueueapc = "NtQueueApcThread" ascii nocase
        $globaladdatom = "GlobalAddAtom" ascii nocase
        $globalgetatom = "GlobalGetAtomName" ascii nocase
        $globalfindatom = "GlobalFindAtom" ascii nocase
        $writeproc = "WriteProcessMemory" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $ntqueueapc and
        ($globaladdatom or $globalgetatom or $globalfindatom) and
        ($writeproc)
}