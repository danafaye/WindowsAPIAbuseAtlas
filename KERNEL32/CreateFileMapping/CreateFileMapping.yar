// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.


rule Suspicious_CreateFileMapping_Usage
{
    meta:
        description = "Detects suspicious use of CreateFileMapping and related APIs for potential in-memory code injection or fileless payload staging"
        author = "ChatGPT for Windows API Abuse Atlas"

    strings:
        $createfilemapping = "CreateFileMapping" ascii nocase
        $api_mapviewoffile = "MapViewOfFile" ascii nocase
        $api_createprocess = "CreateProcess" ascii nocase
        $api_createremotethread = "CreateRemoteThread" ascii nocase

        // Suspicious section or shared memory names often seen in malware
        $susp_section_name1 = "{GUID-" ascii nocase
        $susp_section_name2 = "Global\\" ascii nocase
        $susp_section_name3 = "Local\\" ascii nocase
        $susp_section_name4 = "MsMpSvc" ascii nocase // mimicking legitimate service names used as masquerade

    condition:
        (uint16(0) == 0x5A4D) and // PE file
        $createfilemapping and
        (1 of ($api*)) and
        (1 of ($susp*))
}