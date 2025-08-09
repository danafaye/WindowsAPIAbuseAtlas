// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.


rule Win_API_Abuse_ShellExecute_Suspicious
{
    meta:
        author = "Windows API Abuse Atlas"
        description = "Detects suspicious use of ShellExecute API that may indicate malicious activity"

    strings:
        $ShellExecute = "ShellExecute" ascii wide

        // Suspicious verbs or protocol handlers often abused
        $verb1 = "runas" nocase
        $verb2 = "powershell" nocase
        $verb3 = "cmd.exe" nocase
        $verb4 = "mshta" nocase
        $verb5 = "javascript:" nocase
        $verb6 = "vbscript:" nocase
        $verb7 = "ftp://" nocase
        $verb8 = "http://" nocase
        $verb9 = "https://" nocase
        $verb10 = ".lnk" nocase
        $verb11 = ".url" nocase

    condition:
        uint16(0) == 0x5A4D and // PE file
        filesize < 10MB and
        $ShellExecute and (any of ($verb*))
}
