// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.


rule NtCreateKey_malicious_use
{
    meta:
        description = "Detects malicious use of NtCreateKey via import or string references"
        reference = "windows-api-abuse-atlas"

    strings:
        $NtCreateKey = "NtCreateKey" ascii wide
        $GetProcAddress = "GetProcAddress" ascii wide
        $LoadLibrary = "LoadLibrary" ascii wide
        $ntdll = "ntdll.dll" ascii wide

        // Common registry paths for persistence
        $r1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $r2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide
        $r3 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" ascii wide
        $r4 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        ( 
            $NtCreateKey and
            $GetProcAddress and
            $LoadLibrary and
            $ntdll
        ) and
        (1 of ($r*))
}
