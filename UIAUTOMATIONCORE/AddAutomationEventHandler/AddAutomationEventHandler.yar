// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule detect_UIA_AddAutomationEventHandler_Abuse {
  meta:
    author = "Windows API Abuse Atlas"
    description = "Detects potential malicious use of AddAutomationEventHandler for UI surveillance."


  strings:
    // IUIAutomation interface GUID - represented as raw bytes as COM expects it
    // {ff48dba4-60ef-4201-aa87-54103eef594e}
    // Data1 (A4 DB 48 FF) - little-endian
    // Data2 (EF 60) - little-endian
    // Data3 (01 42) - little-endian
    // Data4 (AA 87 54 10 3E EF 59 4E) - big-endian
    $IUIAutomation_guid_bytes = { A4 DB 48 FF EF 60 01 42 AA 87 54 10 3E EF 59 4E }
    $IUIAutomation_guid = "{ff48dba4-60ef-4201-aa87-54103eef594e}" ascii wide

    // Common COM initialization/object creation APIs
    $s_CoInitialize = "CoInitialize" ascii wide
    $s_CoCreateInstance = "CoCreateInstance" ascii wide

    // APIs for discovering UI elements
    $s_GetRootElement = "GetRootElement" ascii wide
    $s_ElementFromHandle = "ElementFromHandle" ascii wide
    $s_FindFirst = "FindFirst" ascii wide
    $s_FindAll = "FindAll" ascii wide

  condition:
    uint16(0) == 0x5A4D and // MZ header for Windows executable

        (1 of ($IUI*)) and
        (any of ($s_*))
}
