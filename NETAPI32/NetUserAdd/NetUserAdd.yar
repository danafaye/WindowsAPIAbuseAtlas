
// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

import "pe"

rule detect_netuseradd_abuse {

    meta:
        description = "Detects potential abuse of NetUserAdd API for creating user accounts"
        author = "WindowsAPIAbuseAtlas"

    strings:
        $user1 = "admin" ascii wide
        $user2 = "backup" ascii wide
        $user3 = "support" ascii wide
        $user4 = "sysadmin" ascii wide
        $user5 = "temp" ascii wide
        $user6 = "test" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and pe.imports("netapi32.dll", "NetUserAdd")
        and (any of ($user*))
}

