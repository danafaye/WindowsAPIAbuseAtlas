// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_NtQuerySystemInformation_Usage
{
    meta:
        description = "Hunt for binaries that reference NtQuerySystemInformation / ZwQuerySystemInformation"
        author = "Windows API Abuse Atlas"
        date = "2025-10-06"

    strings:
        $NtQuerySystemInformation = "NtQuerySystemInformation"
        $ZwQuerySystemInformation = "ZwQuerySystemInformation"
        $SystemModuleInformation = "SystemModuleInformation"
        $SystemProcessInformation = "SystemProcessInformation"

    condition:
        uint16(0) == 0x5A4D and
        ($NtQuerySystemInformation or $ZwQuerySystemInformation) and
        ($SystemModuleInformation or $SystemProcessInformation)
}