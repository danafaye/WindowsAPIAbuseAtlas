// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_RegCreateKeyEx_Usage
{
    meta:
        description = "Detects binaries that reference RegCreateKeyEx and other registry-manipulating APIs"
        reference = "Windows API Abuse Atlas"
    strings:
        $regCreateKeyEx = "RegCreateKeyEx" ascii
        $regSetValueEx  = "RegSetValueEx" ascii
        $regDeleteValue = "RegDeleteValue" ascii
        $regQueryValueEx = "RegQueryValueEx" ascii
    condition:
        uint16(0) == 0x5A4D and  // PE file
        filesize < 10MB and
        2 of ($reg*)
}

rule detect_suspicious_regcreatekey_activity {
    meta:
        description = "Detects binaries that reference RegCreateKeyEx and other registry-manipulating APIs"
        reference = "Windows API Abuse Atlas"

    strings:
        // Core API call
        $reg_create_key = "RegCreateKey" ascii wide

        // Suspicious registry paths/names (case-insensitive)
        $run_key1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase ascii wide
        $run_key2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase ascii wide
        $service_key = "SYSTEM\\CurrentControlSet\\Services" nocase ascii wide
        $schtasks = "Task Scheduler" nocase ascii wide // Looking for strings related to scheduled tasks
        $cl_sid = "{????????-????-????-????-????????????" // Common Class ID structure, often used for COM hijacking

        // Suspicious data often written to registry (examples)
        $exe_ext = ".exe" ascii wide
        $dll_ext = ".dll" ascii wide
        $powershell_cmd = "powershell.exe -NoP -NonI -Exec Bypass" nocase ascii wide // Common PowerShell evasion
        $base64_encoded = "aHR0c" ascii // Common start of base64 encoded strings (e.g., for commands)

    condition:
        uint16(0) == 0x5A4D and  // PE file
        filesize < 10MB and
        
        // The core API call must be present
        $reg_create_key and

        // At least one suspicious registry path/name
        (
            $run_key1 or
            $run_key2 or
            $service_key or
            $schtasks or
            $cl_sid
        ) and

        // At least one suspicious data string or pattern
        (
            $exe_ext or
            $dll_ext or
            $powershell_cmd or
            $base64_encoded
        )
}