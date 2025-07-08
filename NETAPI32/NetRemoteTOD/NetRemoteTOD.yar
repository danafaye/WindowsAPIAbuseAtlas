
// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Detect_NetRemoteTOD_Import
{
    meta:
        author = "Windows API Abuse Atlas"
        description = "Detects import or string reference to NetRemoteTOD API in PE binaries"

    strings:
        // ASCII string often present in import tables or debug info
        $api1 = "NetRemoteTOD"
        // Wide string variant (UTF-16 LE)
        $api2 = { 4E 00 65 00 74 00 52 00 65 00 6D 00 6F 00 74 00 65 00 54 00 4F 00 44 00 }

    condition:
        any of them
}
