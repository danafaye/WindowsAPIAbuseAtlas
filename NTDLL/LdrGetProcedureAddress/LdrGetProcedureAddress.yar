// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_LdrGetProcedureAddress_Usage
{
    meta:
        description = "Detects potential malicious use of LdrGetProcedureAddress"
        author = "Windows API Abuse Atlas"
        
    strings:
        // Direct string references
        $ldr_str1 = "LdrGetProcedureAddress" ascii wide
        
        // Common suspicious API calls often used with LdrGetProcedureAddress
        $api_ntdll = "ntdll.dll" ascii wide nocase
        $api_virtualalloc = "VirtualAlloc" ascii wide nocase
        $api_virtualprotect = "VirtualProtect" ascii wide nocase
        $api_createthread = "CreateThread" ascii wide nocase
        $api_writeprocessmemory = "WriteProcessMemory" ascii wide nocase
        $api_setthreadcontext = "SetThreadContext" ascii wide nocase
    
        
    condition:
        uint16(0) == 0x5A4D and // PE header "MZ"
        // Basic detection - any reference to the function
        $ldr_str1 and
        
        // Enhanced detection - LdrGetProcedureAddress + suspicious APIs
        (2 of ($api_*))     
}

rule Advanced_LdrGetProcedureAddress_Evasion
{
    meta:
        description = "Detects advanced evasion techniques with LdrGetProcedureAddress"
        author = "Wineows API Abuse Atlas"
        
    strings:
        // Stack strings or split strings
        $split1 = "Ldr" ascii wide
        $split2 = "Get" ascii wide
        $split3 = "Procedure" ascii wide
        $split4 = "Address" ascii wide
        
        // Hash-based resolution indicators
        $hash_pattern1 = { 40 8A ?? 8A ?? 02 ?? 8B ?? C1 ?? ?? 03 ?? }  // Common hash calculation
        $hash_pattern2 = { 33 ?? 8B ?? 8A ?? C1 ?? ?? 03 ?? }          // Another hash variant
        
        // Dynamic resolution patterns
        $getprocaddr = "GetProcAddress" ascii wide nocase
        $loadlibrary = "LoadLibrary" ascii wide nocase
        
    condition:
        uint16(0) == 0x5A4D and // PE header "MZ"
        // Split string technique
        (all of ($split*) and #split1 < 5 and #split2 < 5 and #split3 < 5 and #split4 < 5) or
        
        // Hash-based resolution with library loading
        (any of ($hash_pattern*) and ($getprocaddr or $loadlibrary)) or
        
        // Multiple evasion indicators
        (2 of ($split*) and any of ($hash_pattern*))
}