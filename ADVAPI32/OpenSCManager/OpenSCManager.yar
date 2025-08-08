// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_Service_Control_Abuse
{
    meta:
        description = "Detects use of OpenSCManager along with other service manipulation APIs"
        author = "Windows API Abuse Atlas"

    strings:
        $openscmanager = "OpenSCManager" wide ascii
        $createservice = "CreateService" wide ascii
        $startservice  = "StartService" wide ascii
        $deleteservice = "DeleteService" wide ascii
        $chgsvcconfig  = "ChangeServiceConfig" wide ascii
        $ctrlservice   = "ControlService" wide ascii
        $enumsvcstatus = "EnumServicesStatus" wide ascii
        $openservice   = "OpenService" wide ascii

    condition:
        uint16(0) == 0x5A4D and  // PE file
        $openscmanager and
        2 of ($createservice, $startservice, $deleteservice, $chgsvcconfig, $ctrlservice, $enumsvcstatus, $openservice)
}
