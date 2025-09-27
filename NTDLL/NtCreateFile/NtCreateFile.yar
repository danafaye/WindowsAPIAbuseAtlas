// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule NTCREATEFILE_DYNAMIC_RESOLUTION
{
    meta:
        author = "Windows API Abuse Atlas"
        description = "Flag binaries that contain native NtCreateFile/ZwCreateFile symbols together with dynamic-resolution/import helpers (GetProcAddress/LoadLibrary) or other low-level APIs commonly paired with malicious file staging."
        
    strings:
        // native symbol names (ASCII)
        $NtCreateFile = "NtCreateFile"
        $api_01 = "ZwCreateFile"
        $api_02 = "NtOpenFile"
        $api_03 = "NtWriteFile"
        $api_04 = "NtReadFile"
        $api_05 = "NtCreateSection"
        $api_06 = "NtMapViewOfSection"
        $api_07 = "DeviceIoControl"
        $api_08 = "NtResumeProcess"
        $api_09 = "NtSuspendProcess"

        // kernel32 / resolver helpers (ASCII)
        $api_10 = "GetProcAddress"
        $api_11 = "LoadLibrary"

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $NtCreateFile and
        (2 of ($api_*))           
}
