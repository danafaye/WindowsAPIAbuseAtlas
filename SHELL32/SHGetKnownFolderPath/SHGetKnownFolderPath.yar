// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule Suspicious_SHGetKnownFolderIDList_Usage
{
    meta:
        description = "Detects binaries importing or referencing SHGetKnownFolderIDList"
        author = "Windows API Abuse Atlas"

    strings:
        $SHGetKnownFolderIDList = "SHGetKnownFolderIDList" ascii wide

        // Commonly abused Known Folder GUIDs (ASCII & Wide)
        // Startup: {B97D20BB-F46A-4C97-BA10-5E3608430854}
        $guid_startup_ascii = "{B97D20BB-F46A-4C97-BA10-5E3608430854}" ascii wide

        // Roaming AppData: {3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}
        $guid_appdata_ascii = "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}" ascii wide

        // LocalAppData: {F1B32785-6FBA-4FCF-9D55-7B8E7F157091}
        $guid_localappdata_ascii = "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}" ascii wide

        // Temp: {FDD39AD0-238F-46AF-ADB4-6C85480369C7}
        $guid_temp_ascii = "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}" ascii
    

    condition:
        uint16(0) == 0x5A4D and // PE file
        filesize < 10MB and
        $SHGetKnownFolderIDList and
        (1 of ($guid*))
}