rule Win_APIAbuse_CreateRemoteThread_SuspiciousUsage
{
    meta:
        description = "Detects suspicious use of CreateRemoteThread typically associated with process injection"
        reference = "https://github.com/danafaye/WindowsAPIAbuseAtlas"

    strings:
        $api_CreateRemoteThread = "CreateRemoteThread" ascii
        $api_VirtualAllocEx     = "VirtualAllocEx" ascii
        $api_WriteProcessMemory = "WriteProcessMemory" ascii
        $api_DuplicateHandle        = "DuplicateHandle" ascii

    condition:
        // Require CreateRemoteThread + at least two classic injection APIs
        uint16(0) == 0x5A4D and // PE file
        filesize < 5MB and
        all of them
}
