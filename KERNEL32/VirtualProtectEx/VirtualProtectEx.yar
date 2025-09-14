// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_VirtualProtectEx_Usage
{
    meta:
        description = "Detects suspicious or potentially malicious use of VirtualProtectEx, especially in remote process injection chains."
        reference = "Windows API Abuse Atlas: VirtualProtectEx"

    strings:
        $VirtualProtectEx = "VirtualProtectEx" ascii wide

        $api_VirtualAllocEx      = "VirtualAllocEx" ascii wide
        $api_WriteProcessMemory  = "WriteProcessMemory" ascii wide
        $api_CreateRemoteThread  = "CreateRemoteThread" ascii wide

    condition:
        uint16(0) == 0x5A4D and // PE file
        $VirtualProtectEx and
        ( 2 of ($api*) )    
}
