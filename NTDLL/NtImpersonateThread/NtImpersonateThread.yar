import "pe"

rule NtImpersonateThread_Token_Chaining_General
{
    meta:
        description = "Detects NtImpersonateThread used with other token manipulation APIs (possible privilege escalation)"
        reference = "windows-api-abuse-atlas"
    strings:
        $impersonate = "NtImpersonateThread" ascii nocase
        $duptoken = "DuplicateToken" ascii nocase
        $setthread = "SetThreadToken" ascii nocase
        $openthread = "OpenThreadToken" ascii nocase
        $revert = "RevertToSelf" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $impersonate and
        ($duptoken or $setthread or $openthread or $revert)
}

rule NtImpersonateThread_Thread_Creation_Chain
{
    meta:
        description = "Detects NtImpersonateThread used with thread creation APIs (possible lateral movement or escalation)"
        reference = "windows-api-abuse-atlas"
    strings:
        $impersonate = "NtImpersonateThread" ascii nocase
        $createthread = "NtCreateThread" ascii nocase
        $createthreadex = "NtCreateThreadEx" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $impersonate and
        ($createthread or $createthreadex)
}

rule NtImpersonateThread_TokenTheft_Chain
{
    meta:
        description = "Detects token theft via NtImpersonateThread, SetThreadToken, OpenThreadToken, and thread manipulation APIs"
        reference = "windows-api-abuse-atlas"
    strings:
        $impersonate = "NtImpersonateThread" ascii nocase
        $setthread = "SetThreadToken" ascii nocase
        $openthread = "OpenThreadToken" ascii nocase
        $suspend = "SuspendThread" ascii nocase
        $resume = "ResumeThread" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $impersonate and
        $setthread and
        $openthread and
        ($suspend or $resume)
}