// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_OpenProcessToken_Usage
{
    meta:
        description = "Detects suspicious use of OpenProcessToken (privilege escalation / impersonation)"
        reference = "Windows API Abuse Atlas - OpenProcessToken"

    strings:
        // Core API
        $openprocesstoken = "OpenProcessToken" ascii wide

        // Common malicious companions
        $api_adjusttokenprivileges = "AdjustTokenPrivileges" ascii wide 
        $api_duplicatetoken = "DuplicateToken" ascii wide 
        $api_duplicatetokenex = "DuplicateTokenEx" ascii wide 
        $api_impersonateloggedonuser = "ImpersonateLoggedOnUser" ascii wide 
        $api_setthreadtoken = "SetThreadToken" ascii wide 

    condition:
        uint16(0) == 0x5A4D and  // PE file
        filesize < 10MB and  // Reasonable size limit to avoid false positives
        // Look for OpenProcessToken plus at least one common abuse function
        $openprocesstoken and
        1 of ($api*)
}
