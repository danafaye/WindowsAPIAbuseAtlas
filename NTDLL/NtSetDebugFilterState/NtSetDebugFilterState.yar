// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Detect_NtSetDebugFilterState
{
    meta:
        description = "Simple rule that just looks for the string NtSetDebugFilterState in PE file."
        reference = "windows-api-abuse-atlas"
    strings:
        $api = "NtSetDebugFilterState" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $api
}