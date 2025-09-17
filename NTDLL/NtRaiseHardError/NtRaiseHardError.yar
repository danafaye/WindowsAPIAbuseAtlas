// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.


rule Suspicious_NtRaiseHardError_Usage
{
    meta:
        description = "Detects suspicious dynamic resolution or direct use of NtRaiseHardError in userland binaries"
        reference = "Windows API Abuse Atlas: NtRaiseHardError"

    strings:
        $api_name = "NtRaiseHardError" ascii wide
        $get_proc = "GetProcAddress" ascii wide
        $load_lib = "LoadLibrary" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        all of them
}