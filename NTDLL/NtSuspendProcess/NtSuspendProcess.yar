// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_NtSuspendProcess_Usage
{
    meta:
        description = "Detects potential malicious usage of NtSuspendProcess API"
        reference = "Windows API Abuse Atlas"

    strings:
        $NtSuspendProcess = "NtSuspendProcess" ascii wide

    condition:
        uint16(0) == 0x5A4D and // PE file
        filesize < 10MB and
        $NtSuspendProcess
}