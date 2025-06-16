rule Suspicious_NetLocalGroupGetMembers_Usage {
    meta:
        description = "Detects potential abuse of NetLocalGroupGetMembers API for privilege discovery"
        author = "Windows API Abuse Atlas"

    strings:
        // API Names
        $api1 = "NetLocalGroupGetMembers" ascii wide
        $api2 = "NetLocalGroupEnum" ascii wide
        $api3 = "NetUserGetLocalGroups" ascii wide
        
        // Common Group Names
        $group1 = "Administrators" ascii wide nocase
        $group2 = "Domain Admins" ascii wide nocase
        $group3 = "Enterprise Admins" ascii wide nocase
        $group4 = "Remote Desktop Users" ascii wide nocase
        
        // Common Enumeration Patterns
        $enum1 = "wksta" ascii wide nocase
        $enum2 = "domain" ascii wide nocase
        $enum3 = "computer" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and     // PE file
        filesize < 10MB and         // Size constraint
        (
            // Additional context
            (1 of ($api*)) and
            (1 of ($group*)) and
            (1 of ($enum*))
        )
}