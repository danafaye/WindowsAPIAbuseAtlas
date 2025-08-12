// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.


rule Hunt_CreateNamedPipe_Usage
{
    meta:
        description = "Hunting rule to find any binary referencing CreateNamedPipe"
        purpose = "Threat hunting only – expect high false positives"

    strings:
        $CreateNamedPipe = "CreateNamedPipe" ascii wide

        // Related named pipe server APIs
        $api_1 = "ConnectNamedPipe" ascii wide
        $api_2 = "CallNamedPipe" ascii wide
        $api_3 = "WaitNamedPipeA" ascii wide

        // Generic IO functions often used with pipes
        $readfile      = "ReadFile" ascii wide
        $writefile     = "WriteFile" ascii wide

    condition:
        (uint16(0) == 0x5A4D) and // PE file
        filesize < 10MB and // reasonable size limit
        $CreateNamedPipe and
        (1 of ($api*)) and
        ($readfile or $writefile)
}