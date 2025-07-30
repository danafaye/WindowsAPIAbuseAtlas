// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.
import "pe"

rule Suspicious_PssCaptureSnapshot_Usage
{
    meta:
        description = "Detects binaries abusing PssCaptureSnapshot in combination with typical combination that indicates malicious activity."
        reference = "Windows API Abuse Atlas"

    strings:
        $PssCaptureSnapshot = "PssCaptureSnapshot" ascii wide
        $NtPssCaptureSnapshot = "NtPssCaptureSnapshot" ascii wide
        $api_1 = "PssQuerySnapshot" ascii wide
        $api_2 = "PssWalkMarker" ascii wide
        $api_3 = "PssFreeSnapshot" ascii wide
        $api_4 = "NtReadVirtualMemory" ascii wide
        $api_5 = "OpenProcess" ascii wide
        $api_6 = "GetProcAddress" ascii wide    

    condition:
        uint16(0) == 0x5A4D and  // PE header
        filesize < 5MB and
        // Not signed by Microsoft
        not for any i in (0..pe.number_of_signatures): 
            (pe.signatures[i].issuer contains "Microsoft") and
        ($PssCaptureSnapshot or $NtPssCaptureSnapshot) and
        (
            // Check for common post-snapshot APIs that indicate malicious use
            2 of ($api_*)
        )

}
