rule Suspicious_EtwNotificationRegister_Usage
{
    meta:
        author = "Windows API Abuse Atlas"
        description = "Detects suspicious usage of EtwNotificationRegister, often abused for telemetry-aware evasion"

    strings:
        $api_name1 = "EtwNotificationRegister" ascii wide 
        $api_name2 = "EtwSetNotificationCallback" ascii wide 

    condition:
        uint16(0) == 0x5A4D and // PE header "MZ"

        // Detect either static import or dynamic resolution of EtwNotificationRegister or related APIs
        $api_name1 or $api_name2
}
