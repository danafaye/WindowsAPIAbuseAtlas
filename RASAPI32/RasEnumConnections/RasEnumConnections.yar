// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule RASAPI32_RasEnumConnections
{
    meta:
        author = "Windows API Abuse Atlas"
        description = "Detects the presence of the RasEnumConnections function, which can be used to enumerate active RAS connections."

    strings:
        $func_name = "RasEnumConnections" ascii wide

    condition:
        uint16(0) == 0x5A4D and // PE file
        filesize < 10MB and
        any of them
}