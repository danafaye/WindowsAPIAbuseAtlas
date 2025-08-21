// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule malware_SetSearchPathMode_use
{
       meta:
        author = "Windows API Abuse Atlas"
        description = "Detects import of SetSearchPathMode API, which can be a sign of malicious DLL side-loading."
        
    strings:
        $SetSearchPathMode = "SetSearchPathMode" ascii wide

    condition:
        // Ensure the file is a PE executable
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        
        $SetSearchPathMode 
}