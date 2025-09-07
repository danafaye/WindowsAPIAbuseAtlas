// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.


rule NtCreateKey_malicious use
{
    meta:
        description = "Detects malicious use of NtCreateKey via import or string references"
        reference = "windows-api-abuse-atlas"
    strings:
        $NtCreateKey = "NtCreateKey" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $NtCreateKey
}
