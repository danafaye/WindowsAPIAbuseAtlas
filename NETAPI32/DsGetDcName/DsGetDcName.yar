import "pe"

rule Hunt_DsGetDcName_Usage
{
    meta:
        description = "Hunt rule for binaries referencing DsGetDcName, used in domain controller enumeration"
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"
    strings:
        // API references
        $dsgetdc = "DsGetDcName" ascii wide

        // Dynamic resolution patterns
        $loadlib = "LoadLibrary" ascii wide
        $getproc = "GetProcAddress" ascii wide

        // Optional supporting context
        $domaininfo = "DomainControllerInfo" ascii wide
        $netjoin = "NetGetJoinInformation" ascii wide
        $dsgetsite = "DsGetSiteName" ascii wide

    condition:
        uint16(0) == 0x5A4D and // PE file check
        $dsgetdc and
        (
            any of ($loadlib, $getproc) or
            any of ($domaininfo, $netjoin, $dsgetsite)
        )
}

rule Hunt_DsGetDcName_Imported
{
    meta:
        description = "Just looking for imports of DsGetDcName"
    condition:
        pe.imports("NetApi32.dll", "DsGetDcNameW") or
        pe.imports("NetApi32.dll", "DsGetDcNameA")
}