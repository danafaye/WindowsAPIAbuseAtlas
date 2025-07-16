// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_NtQueryVirtualMemory_Use
{
    meta:
        description = "Detects suspicious use of NtQueryVirtualMemory alongside common memory reconnaissance APIs"
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"
        
    strings:
        $api1 = "NtQueryVirtualMemory"
        $api2 = "OpenProcess"
        $api3 = "VirtualQueryEx"
        $api4 = "ReadProcessMemory"
        $api5 = "NtReadVirtualMemory"

    condition:
        uint16(0) == 0x5A4D and  // PE file magic number 'MZ'
        (all of ($api*))
}