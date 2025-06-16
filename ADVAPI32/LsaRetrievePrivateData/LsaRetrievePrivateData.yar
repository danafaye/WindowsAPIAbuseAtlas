// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_LsaRetrievePrivateData_Usage
{
    meta:
        description = "Detects use of LsaRetrievePrivateData to pull secrets like SCPassword from LSA"
        reference = "Windows API Abuse Atlas"

    strings:
        $api1 = "LsaRetrievePrivateData" ascii
        $api2 = "LsaOpenPolicy" ascii
        $perm = "POLICY_GET_PRIVATE_INFORMATION" ascii
        $key1 = "SCPassword" ascii
        $key2 = "AppPoolPassword" ascii
        $key3 = "ServiceAccountPassword" ascii

    condition:
        uint16(0) == 0x5A4D and  // PE file
        2 of ($api*) and
        1 of ($key*) and
        $perm
}