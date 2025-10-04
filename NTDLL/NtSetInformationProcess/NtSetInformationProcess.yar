// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_NtSetInformationProcess_Usage
{
    meta:
        description = "Detects potential malicious usage of NtSetInformationProcess API"
        reference = "Windows API Abuse Atlas"

    strings:
        $NtSetInformationProcess = "NtSetInformationProcess" ascii wide
        $api_ProcessInstrumentationCallback = "ProcessInstrumentationCallback"
        $api_InstrumentationCallback = "InstrumentationCallback"
        $api_api_EtwEventWrite   = "EtwEventWrite"
        $api_EtwRegister   = "EtwRegister"
        $api_EtwWrite   = "EtwWrite"
        $api_GetProcAddress = "GetProcAddress"
        $api_LoadLibrary = "LoadLibrary"
    condition:
        uint16(0) == 0x5A4D and // PE file
        filesize < 10MB and
        $NtSetInformationProcess and 
        (3 of ($api*))
}