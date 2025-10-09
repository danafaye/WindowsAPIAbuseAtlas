// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.

rule CommonlyAbused_COM_CLSIDs_Binary
{
    meta:
        description = "Detects binary representations of commonly abused COM CLSIDs"
        reference = "Windows API Abuse Atlas"

    strings:
        $CoCreateInstanceEx = "CoCreateInstanceEx" ascii wide

        $clsid_ShellWindows        = { 72 59 A0 9B A8 F6 CF 11 A4 42 00 A0 C9 0A 8F 39 }
        $clsid_ShellApplication    = { 20 96 70 13 79 C2 CE 11 A4 9E 44 45 53 54 00 00 }
        $clsid_WScriptShell1       = { D5 4D C2 72 0A D7 8B 43 8A 42 98 42 4B 88 AF B8 }
        $clsid_WScriptShell2       = { C5 10 3B D6 46 BB 90 49 A9 4F E4 0B 9D 52 01 60 } 
        $clsid_FileSystemObject    = { 32 8F 07 F5 51 C5 D3 11 89 B9 00 00 F8 1F E2 21 }
        $clsid_Msxml2DOMDocument6  = { C0 69 D9 88 92 F1 D4 11 A6 5F 00 40 96 32 51 E5 }
        $clsid_IEWebBrowser        = { 68 5B 17 9E 2A F5 D8 11 B9 A5 50 50 54 50 30 30 }
        $clsid_InternetExplorerApp = { 01 DF 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
        $clsid_IE_alt              = { 01 0C B0 DC 0F 57 9B 4A 8D 69 19 9F DB A5 72 3B }
        $clsid_MS_XMLHTTP          = { 63 E3 EA 45 2A 12 5A 44 97 B6 3D E8 90 E7 86 F8 }
        $clsid_MS_Outlook          = { 3A F0 06 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
    condition:
        uint16(0) == 0x5A4D and // PE file
        filesize < 10MB and
        $CoCreateInstanceEx and
        any of ($clsid*)
}
