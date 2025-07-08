// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_ControlService_Abuse
{
    meta:
        author = "Windows API Abuse Atlas"
        description = "Detects binaries abusing ControlService with other service manipulation APIs"

    strings:
        $a1 = "OpenSCManagerA" wide ascii
        $a2 = "OpenSCManagerW" wide ascii
        $b1 = "OpenServiceA" wide ascii
        $b2 = "OpenServiceW" wide ascii
        $c1 = "ControlService" wide ascii
        $d1 = "ChangeServiceConfigA" wide ascii
        $d2 = "ChangeServiceConfigW" wide ascii
        $e1 = "ChangeServiceConfig2A" wide ascii
        $e2 = "ChangeServiceConfig2W" wide ascii
        $f1 = "CreateServiceA" wide ascii
        $f2 = "CreateServiceW" wide ascii
        $g1 = "DeleteService" wide ascii
        $h1 = "StartServiceA" wide ascii
        $h2 = "StartServiceW" wide ascii

    condition:
        (uint16(0) == 0x5A4D) and  // PE file
        $c1 and 
        3 of ($a*,$b*,$d*,$e*,$f*,$g*,$h*)  // Must include ControlService + at least 3 others
}
