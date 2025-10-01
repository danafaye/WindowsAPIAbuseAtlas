// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_WinHttp_Strings
{
    meta:
        author = "Windows API Abuse Atlas"
        description = "Detects binaries that reference WinHTTP API strings such as WinHttpConnect"
        date = "2025-09-30"
    strings:
        $w1 = "WinHttpConnect" wide nocase
        $a1 = "WinHttpOpenRequest" ascii nocase
        $a2 = "WinHttpSendRequest" ascii nocase
    condition:
        (uint16(0) == 0x5A4D) and /* basic PE check */
        all of them
}