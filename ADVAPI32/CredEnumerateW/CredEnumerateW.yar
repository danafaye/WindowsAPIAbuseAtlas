
// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Potential_CredEnumerateW_Abuse
{
    meta:
        description = "Detects potential abuse of CredEnumerateW API in credential-harvesting malware"
        reference = "Windows API Abuse Atlas - CredEnumerateW"

    strings:
        $s1 = "CredEnumerate" wide ascii
        $s2 = "CredentialBlob" wide ascii
        $s3 = "TargetName" wide ascii
        $s4 = "UserName" wide ascii
        $s5 = "CredFree" wide ascii
        $s6 = "CRED_ENUMERATE" wide ascii

    condition:
        uint16(0) == 0x5A4D and
        2 of ($s1, $s2, $s3, $s4, $s5, $s6)
}