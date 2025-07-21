// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.
import "pe"

rule Suspicious_EnumProcesses_Usage
{
    meta:
        description = "Detects binaries abusing EnumProcesses in combination with typical post-enumeration APIs"
        reference = "Windows API Abuse Atlas"

    strings:
        $EnumProcesses = "EnumProcesses" ascii wide
        $K32EnumProcesses = "K32EnumProcesses" ascii wide
        $a1 = "OpenProcess" ascii wide
        $a2 = "EnumProcessModules" ascii wide
        $a3 = "GetModuleBaseName" ascii wide
        $a4 = "QueryFullProcessImageNameW" ascii wide
        $a5 = "CreateToolhelp32Snapshot" ascii wide
        $a6 = "Process32FirstW" ascii wide
        $a7 = "Process32NextW" ascii wide

    condition:
        uint16(0) == 0x5A4D and  // PE header
        ($EnumProcesses or $K32EnumProcesses) and
        3 of ($a*) and
        filesize < 2MB and
        not for any i in (0..pe.number_of_signatures): 
            (pe.signatures[i].issuer contains "Microsoft")
}
