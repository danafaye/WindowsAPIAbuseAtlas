// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Possible_EnumProcessModules_API_Usage
{
    meta:
        description = "Detects binaries importing or referencing EnumProcessModules"
        reference = "Windows API Abuse Atlas - EnumProcessModules"

    strings:
        $import1 = "EnumProcessModules" ascii
        $import2 = "EnumProcessModulesEx" ascii
        $dll = "psapi.dll" ascii

    condition:
        uint16(0) == 0x5A4D and // PE file
        filesize < 10MB and
        any of ($import*) and $dll
}

rule EnumProcessModules_Followed_By_Injection_APIs
{
    meta:
        description = "Detects binaries referencing EnumProcessModules along with common injection APIs"
        reference = "Windows API Abuse Atlas - EnumProcessModules"

    strings:
        $enum = "EnumProcessModules" ascii
        $inj1 = "WriteProcessMemory" ascii
        $inj2 = "CreateRemoteThread" ascii
        $inj3 = "VirtualProtectEx" ascii
        $inj4 = "VirtualAllocEx" ascii

    condition:
        uint16(0) == 0x5A4D and // PE file
        filesize < 10MB and
        $enum and (1 of ($inj*))
}

rule EnumProcessModules_AntiAnalysis_Check
{
    meta:
        description = "Detects use of EnumProcessModules to look for analysis or security tools"
        reference = "Windows API Abuse Atlas - EnumProcessModules"
    strings:
        // Module enumeration
        $enum = "EnumProcessModules" ascii
        $enumEx = "EnumProcessModulesEx" ascii

        // Suspicious DLLs / sandbox indicators
        $dll1 = "sbiedll.dll" ascii
        $dll2 = "api_log.dll" ascii
        $dll3 = "dir_watch.dll" ascii
        $dll4 = "vmcheck.dll" ascii
        $dll5 = "pstorec.dll" ascii
        $dll6 = "snxhk.dll" ascii
        $dll7 = "SbieDll.dll" ascii
        $dll8 = "dbghelp.dll" ascii
        $dll9 = "avghookx.dll" ascii
        $dll10 = "avghooka.dll" ascii
        $dll11 = "vmtoolsd.exe" ascii
        $dll12 = "vboxhook.dll" ascii

    condition:
        uint16(0) == 0x5A4D and // PE file
        filesize < 10MB and
        (1 of ($enum, $enumEx)) and (2 of ($dll*))
}

rule EnumProcessModules_SecurityProductCheck
{
    meta:
        description = "Detects use of EnumProcessModules for EDR or AV detection"
        reference = "Windows API Abuse Atlas - EnumProcessModules"

    strings:
        // API use
        $api1 = "EnumProcessModules" ascii
        $api2 = "EnumProcessModulesEx" ascii

        // Known EDR/AV DLLs
        $sec1 = "amsi.dll" ascii
        $sec2 = "avcuf32.dll" ascii
        $sec3 = "avcuf64.dll" ascii
        $sec4 = "bdcore.dll" ascii
        $sec5 = "kasperskylab" ascii
        $sec6 = "crowdstrike" ascii
        $sec7 = "cyoptics.dll" ascii
        $sec8 = "cyvrss.dll" ascii
        $sec9 = "edrsensor.dll" ascii
        $sec10 = "eawt.dll" ascii
        $sec11 = "trapsagent" ascii
        $sec12 = "cb.exe" ascii
        $sec13 = "carbonblack" ascii
        $sec14 = "SentinelAgent.dll" ascii
        $sec15 = "mfetdi2k.sys" ascii

    condition:
        uint16(0) == 0x5A4D and // PE file
        filesize < 10MB and
        (1 of ($api*)) and (3 of ($sec*))
}
