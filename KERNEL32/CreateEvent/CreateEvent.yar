// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_CreateEvent_Use
{
    meta:
        author = "Windows API Abuse Atlas"
        description = "Detects potential malicious use of CreateEvent (named events, single-instance enforcement, or suspicious context)."
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"
        date = "2025-09-04"
        version = "1.0"

    strings:
        $CreateEvent = "CreateEvent" ascii wide

        // Common suspicious substrings in named events
        $name_global = "Global\\" ascii wide
        $name_local = "Local\\" ascii wide

    condition:
        (uint16(0) == 0x5A4D) and // PE file
        filesize < 10MB and
        $CreateEvent and
        (any of ($name*))
}
