// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_LsaOpenPolicy_Usage
{
    meta:
        author = "Windows API Abuse Atlas"
        description = "Detects potential usage of the LsaOpenPolicy API"
        scope = "research / hunting"
        note = "High false positive risk – intended for threat hunting, not production detection."

    strings:
        $LsOpenPolicy = "LsOpenPolicy" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        $LsaOpenPolicy
}
