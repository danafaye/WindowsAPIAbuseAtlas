// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule WIN_API_ImpersonateLoggedOnUser_Abuse_AllInOne
{
  meta:
    author      = "Windows API Abuse Atlas"
    description = "Hunt for binaries/scripts that import or dynamically resolve ImpersonateLoggedOnUser along with typical token abuse & lateral movement helpers."

  strings:
    // Direct function name (static or in dyn-res)
    $ImpersonateLoggedOnUser = "ImpersonateLoggedOnUser" ascii wide
 
    // Token acquisition & manipulation (common neighbors)
    $tok_openproc_a  = "OpenProcessToken" ascii
    $tok_openthread  = "OpenThreadToken" ascii
    $tok_dup_a       = "DuplicateToken" ascii
    $tok_adjpriv     = "AdjustTokenPrivileges" ascii
    $tok_setthread   = "SetThreadToken" ascii
    $tok_revert      = "RevertToSelf" ascii
    $tok_logon       = "LogonUser" ascii
    $tok_ntsetinfo   = "NtSetInformationToken" ascii

    // Post-impersonation execution & movement helpers
    $post_cpasuser     = "CreateProcessAsUser" ascii
    $post_cpwtoken     = "CreateProcessWithToken" ascii
    $post_net_use         = "NetUseAdd" ascii
    $post_rpc_auth        = "RpcBindingSetAuthInfo" ascii
    $post_wmi_spawn       = "Win32_Process" ascii
    $post_psexec_like     = "SERVICE_CONTROL_START" ascii

  condition:
    uint16(0) == 0x5A4D and
    filesize < 5MB and
    $ImpersonateLoggedOnUser and
    ((2 of ($tok*)) and (1 of ($post*)))
}
