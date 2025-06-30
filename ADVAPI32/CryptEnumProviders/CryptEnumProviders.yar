// Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily 
// for threat hunting and research purposes — not for deployment in detection systems that 
// require a low false positive rate. Please review and test in your environment before use.
rule Suspicious_CryptEnumProviders_Usage
{
    meta:
        description = "Detects use of CryptEnumProviders API, often used for cryptographic provider enumeration or key recon"
        reference = "Windows API Abuse Atlas"
    strings:
        // Main target API
        $crypt_enum = "CryptEnumProviders" ascii wide

        // Supporting indicators
        $acquire_ctx = "CryptAcquireContext" ascii wide
        $export_key = "CryptExportKey" ascii wide
        $sign_hash = "CryptSignHash" ascii wide

    condition:
        uint16(0) == 0x5A4D and // PE file
        filesize > 10MB and // Ensure it's a reasonably sized file
        $crypt_enum and
        any of ($acquire_ctx, $export_key, $sign_hash)
}