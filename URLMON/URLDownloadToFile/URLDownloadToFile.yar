// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_Uses_of_URLDownloadToFile
{
    meta:
        author = "Windows API Abuse Atlas"
        description = "Heuristic: PE that imports URLDownloadToFile or contains explicit URL-download strings."

    strings:
        $URLDownloadToFile = "URLDownloadToFile" ascii nocase
        $http_marker = "http://" ascii nocase
        $https_marker = "https://" ascii nocase
        $temp_env = "%TEMP%" ascii nocase
        $temp_path = "\\\\Temp\\\\" ascii nocase

    condition:
        (uint16(0) == 0x5A4D) and /* basic PE check */
        $URLDownloadToFile and
        any of ($http_marker, $https_marker, $temp_env, $temp_path)
}

