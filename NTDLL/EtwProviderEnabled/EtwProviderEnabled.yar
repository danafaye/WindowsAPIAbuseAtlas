rule Potential_EtwProviderEnabled_Abuse
{
    meta:
        description = "Detects binaries that reference EtwProviderEnabled, which may indicate ETW evasion or stealthy execution logic"
        author = "Windows API Abuse Atlas"

    strings:
        $etw_string1 = "EtwProviderEnabled" ascii
        $etw_string2 = "EtwEventWrite" ascii
        $etw_string3 = "EtwEventRegister" ascii
        $etw_string4 = "EtwWriteEx" ascii
        $etw_bytes = { 48 89 ?? ?? ?? 48 83 EC ?? E8 ?? ?? ?? ?? }  // generic MOV+CALL pattern around ETW APIs

    condition:
        (1 of ($etw_string*)) or ($etw_bytes)
}
