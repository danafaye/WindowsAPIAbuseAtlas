// Just for research.  There is no other reason to use this rule.

import "pe"

rule Detect_PSAPI_DLL_Import {
    meta:
        description = "Detects PE files importing psapi.dll"
    condition:
        pe.imports("psapi.dll") > 0
}