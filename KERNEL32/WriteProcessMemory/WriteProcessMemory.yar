import "pe"

rule DLL_Injection_LoadLibrary_WriteProcessMemory
{
    meta:
        description = "Detect classic DLL injection behavior using WriteProcessMemory + LoadLibrary"
        author = "Windows API Abuse Atlas"
    strings:
        $wpm = "WriteProcessMemory"
        $load = "LoadLibrary" // LoadLibraryA or LoadLibraryW
    condition:
        filesize < 10MB and
        pe.is_pe and
        1 of ($wpm, $load) and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        pe.imports("kernel32.dll", "LoadLibraryA") or pe.imports("kernel32.dll", "LoadLibraryW")
}

rule Reflective_DLL_Injection
{
    meta:
        description = "Detect reflective DLL injection stub or loader"
    strings:
        $m1 = "NTDLL.DLL"
        $m2 = "RtlMoveMemory"
        $m3 = "VirtualAlloc"
        $m4 = { 4C 8B DC 48 83 EC ?? 48 8D 05 ?? ?? ?? ?? } // common prologue for reflective stubs
    condition:
        filesize < 10MB and
        pe.is_pe and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        all of them
}

rule Shellcode_Injection_WPM
{
    meta:
        description = "Detect shellcode injection setup using WriteProcessMemory + RWX memory"
    strings:
        $virtualalloc = "VirtualAllocEx"
        $wpm = "WriteProcessMemory"
        $createthread = "CreateRemoteThread"
        $createthread_nt = "NtCreateThreadEx"
    condition:
        filesize < 10MB and
        pe.is_pe and
        all of ($virtualalloc, $wpm) and
        any of ($createthread, $createthread_nt)
}

rule Process_Hollowing_WPM
{
    meta:
        description = "Detect process hollowing behavior (CreateSuspended + WPM)"
    strings:
        $create = "CreateProcess" // CreateProcessA or CreateProcessW
        $wpm = "WriteProcessMemory"
        $resume = "ResumeThread"
    condition:
        filesize < 10MB and
        pe.is_pe and
        all of them and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        pe.imports("kernel32.dll", "ResumeThread")
}

rule Thread_Hijacking
{
    meta:
        description = "Detect thread hijacking using WPM + SetThreadContext"
    strings:
        $wpm = "WriteProcessMemory"
        $setctx = "SetThreadContext"
        $getctx = "GetThreadContext"
    condition:
        filesize < 10MB and
        pe.is_pe and
        all of them
}

rule IAT_EAT_Patching
{
    meta:
        description = "Detect binaries manipulating import/export tables"
    strings:
        $iat = "ImportAddressTable"
        $eat = "ExportAddressTable"
        $wpm = "WriteProcessMemory"
        $patch = "patch" wide ascii
    condition:
        filesize < 10MB and
        pe.is_pe and
        $wpm and 1 of ($iat, $eat) and $patch
}

rule Config_Injection_WPM
{
    meta:
        description = "Detect config blob writing using WPM"
    strings:
        $wpm = "WriteProcessMemory"
        $cfg = "config" wide ascii
        $aes = "AES" ascii
    condition:
        filesize < 10MB and
        pe.is_pe and
        all of them
}

rule Interprocess_Staging
{
    meta:
        description = "Detect staging via memory writing and named pipes"
    strings:
        $wpm = "WriteProcessMemory"
        $pipe = "\\\\.\\pipe\\" ascii
    condition:
        filesize < 10MB and
        pe.is_pe and
        all of them
}

rule Memory_Stomping_WPM
{
    meta:
        description = "Detect code injection into trusted processes using WPM"
    strings:
        $wpm = "WriteProcessMemory"
        $explorer = "explorer.exe"
        $svchost = "svchost.exe"
    condition:
        filesize < 10MB and
        pe.is_pe and
        $wpm and 1 of ($explorer, $svchost)
}
