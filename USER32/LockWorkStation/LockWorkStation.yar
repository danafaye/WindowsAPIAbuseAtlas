import "pe"

rule Detect_LockWorkStation_Import
{
    meta:
        author = "ChatGPT"
        description = "Detects PE files importing LockWorkStation from user32.dll"
        reference = "Windows API Abuse Atlas - LockWorkStation"
        date = "2025-06-30"
        severity = "low"

    strings:
        $lock_workstation = "LockWorkStation" ascii wide

    condition:
        uint16(0) == 0x5A4D // Check for MZ header
        and pe.imports("user32.dll", "LockWorkStation")
        and pe.number_of_sections > 2 // Ensure there are sections in the PE file
        and $lock_workstation
}

