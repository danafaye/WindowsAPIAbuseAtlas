// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Windows_API_Abuse_Driver_Load_with_PrivEsc
{
   meta:
        description = "Detects suspicious usage of NtMapViewOfSection API commonly abused in process injection"
        author = "WindowsAPIAbuseAtlas"
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"
    strings:
        // Privilege escalation APIs often abused
        $adjust_token = "AdjustTokenPrivileges" ascii wide
        $impersonate_thread = "NtImpersonateThread" ascii wide
        $set_info_thread = "NtSetInformationThread" ascii wide
        $open_process_token = "OpenProcessToken" ascii wide
        $lookup_privilege_value = "LookupPrivilegeValue" ascii wide
        $open_thread_token = "OpenThreadToken" ascii wide

        // Driver loading APIs
        $ntload = "NtLoadDriver" ascii wide
        //$zwload = "ZwLoadDriver" ascii wide

        // Registry path often used to point to drivers
        $regpath = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" ascii wide

        // Known vulnerable or commonly abused driver names (including cryptomining)
        $vuln_driver1 = "rwe.sys" ascii wide
        $vuln_driver2 = "cvss.sys" ascii wide
        $vuln_driver3 = "kbeu.sys" ascii wide
        $vuln_driver4 = "dbutil_2_3.sys" ascii wide
        $vuln_driver5 = "compbatt.sys" ascii wide
        $vuln_driver6 = "iqvw64e.sys" ascii wide
        $vuln_driver7 = "capcom.sys" ascii wide
        $vuln_driver8 = "tdx.sys" ascii wide
        $vuln_driver9 = "samsrv.sys" ascii wide
        $vuln_driver10 = "beep.sys" ascii wide
        $vuln_driver11 = "RTCore64.sys" ascii wide
        $vuln_driver12 = "nvlddmkm.sys" ascii wide
        $vuln_driver13 = "atikmdag.sys" ascii wide
        $vuln_driver14 = "procmon64.sys" ascii wide
        $vuln_driver15 = "amsint64.sys" ascii wide

    condition:
        // Require driver loading API + registry path + driver file extension + vulnerable driver
        // AND privilege escalation API somewhere in the file
        $ntload and 
        $regpath and 
        any of ($vuln_driver*) and 
        any of (
            $adjust_token, $impersonate_thread, $set_info_thread, $open_process_token,
            $lookup_privilege_value, $open_thread_token
        )
}