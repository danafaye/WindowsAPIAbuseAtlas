rule Suspicious_WFP_Manipulation
{
    meta:
        description = "Detects binaries that import or reference Windows Filtering Platform (WFP) APIs often abused for network manipulation"
        reference = "Windows API Abuse Atlas"

    strings:
        // WFP API usage
        $fwpm1 = "FwpmEngineOpen" wide ascii
        $fwpm2 = "FwpmFilterAdd" wide ascii
        $fwpm3 = "FwpmFilterRemove" wide ascii
        $fwpm4 = "FwpmCalloutAdd" wide ascii
        $fwpm5 = "FwpmCalloutRemove" wide ascii

        // Indicators of custom C2/packet manipulation
        $c2_1 = "SetWindowsHookEx" wide ascii
        $c2_2 = "CreateThread" wide ascii
        $c2_3 = "recv" wide ascii
        $c2_4 = "send" wide ascii
        $net1  = "connect" wide ascii

    condition:
        (uint16(0) == 0x5A4D) and // PE file
        (2 of ($fwpm*)) and (2 of ($c2_*) or $net1)
}
