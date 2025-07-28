// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.


rule Detect_CreateFileTransacted
{
    meta:
        description = "Detects presence of CreateFileTransacted API usage"
        author = "Windows API Abuse Atlas"

    strings:
        $api_name = "CreateFileTransacted" ascii nocase

    condition:
        (uint16(0) == 0x5A4D) and // PE file
        $api_name
}