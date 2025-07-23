import "pe"

rule Suspicious_CreateToolhelp32Snapshot_Abuse
{
    meta:
        description = "Detects potential abuse of CreateToolhelp32Snapshot for process/module enumeration"
        reference = "Windows API Abuse Atlas"

    strings:
        $api1 = "CreateToolhelp32Snapshot" ascii
        $api2 = "Process32First" ascii
        $api3 = "Process32Next" ascii
        $api4 = "Module32First" ascii
        $api5 = "Module32Next" ascii

    condition:
        uint16(0) == 0x5A4D and // PE file
        $api1 and 
        1 of ($api2, $api3, $api4, $api5) and
        filesize < 2MB
}
