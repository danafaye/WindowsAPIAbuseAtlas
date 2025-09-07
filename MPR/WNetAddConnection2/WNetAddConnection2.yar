// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.


rule Suspicious_WNetAddConnection2
{
    meta:

        description = "Detects potential malicious use of WNetAddConnection2 via import or string references"
        reference = "Windows API Abuse Atlas: WNetAddConnection2"

    strings:
        $WNetAddConnection2A = "WNetAddConnection2A" ascii wide

    condition:
        $WNetAddConnection2A
}
