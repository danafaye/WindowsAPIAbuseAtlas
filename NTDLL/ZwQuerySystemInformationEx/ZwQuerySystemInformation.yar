rule Detect_ZwQuerySystemInformationEx_Usage
{
    meta:
        author = "Windows API Abuse Atlas"
        description = "Detect attempts to resolve or use ZwQuerySystemInformationEx in ntdll.dll"
        
    strings:
        // The function name as an ASCII string (common to see in export table parsing or GetProcAddress)
        $func_name = "ZwQuerySystemInformation" ascii wide

        // Common suspicious string obfuscation patterns (hex encoded fragments or scrambled strings often seen)
        $obf_1 = { 5A 77 51 75 65 72 79 53 79 73 74 65 6D 49 6E 66 6F } // "ZwQuerySystemInfo" fragment in ASCII hex
        $obf_2 = { 51 75 65 72 79 53 79 73 74 65 6D } // "QuerySystem" substring
        
        // Suspicious PE export table parsing strings
        $export_parse_1 = "GetProcAddress" ascii
        $export_parse_2 = "LoadLibrary" ascii
        $export_parse_3 = "ntdll.dll" ascii wide

    condition:
        // Presence of the function name string in ASCII or wide char format
        any of ($func_name) or
        
        // Presence of obfuscated string fragments related to function name plus signs of export table parsing
        (any of ($obf_*) and any of ($export_parse_*)) or
        
        // If the binary is trying to manually resolve exports by combining LoadLibrary/GetProcAddress and suspicious string fragments
        (all of ($export_parse_*) and any of ($obf_*))
}