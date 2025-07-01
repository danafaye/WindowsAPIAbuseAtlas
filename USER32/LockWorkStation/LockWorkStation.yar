// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.


import "pe"

rule Detect_LockWorkStation_Import
{
    meta:
        description = "Detects PE files importing LockWorkStation from user32.dll"
        reference = "Windows API Abuse Atlas - LockWorkStation"
    strings:
        $lock_workstation = "LockWorkStation" ascii wide

    condition:
        uint16(0) == 0x5A4D // Check for MZ header
        and pe.imports("user32.dll", "LockWorkStation")
        and pe.number_of_sections > 2 // Ensure there are sections in the PE file
        and $lock_workstation
}

