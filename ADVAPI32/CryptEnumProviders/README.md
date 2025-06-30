### 🔍 CryptEnumProviders — Crypto Recon Made Simple
### 🚀 Executive Summary  

### 🔍 What is CryptEnumProviders?
`CryptEnumProviders` walks through the list of installed cryptographic service providers (CSPs) on a system. These providers are the engine rooms behind Windows cryptography—they handle everything from encrypting files to signing code to managing private keys. Each CSP defines what algorithms it supports (RSA, AES, RC4, etc.), how it stores keys, and what level of security it enforces. Some are software-based, others use hardware (like smart cards or TPMs), and a few stick around for legacy compatibility. This API lets software query the available providers, figure out what’s supported, and decide which one to use when working with the broader CryptoAPI stack. If you're touching crypto on Windows, CSPs are where the rubber meets the road.

### 🚩 Why It Matters  
Red teamers and malware love knowing what crypto options are on the table, and `CryptEnumProviders` is how they take inventory. For defenders, it’s a low-noise API that can quietly signal intent—anything from prepping for credential theft to checking for legacy crypto that's easier to exploit. If you’re hunting for staging behaviors before the real damage starts, this one’s worth keeping on your radar.

### 🧬 How Attackers Abuse It  
Attackers use `CryptEnumProviders` to fingerprint the crypto stack before committing to a move. It’s quiet recon that tells them which cryptographic service providers are installed, especially if any weak or legacy ones like “Microsoft Base Cryptographic Provider v1.0” are hanging around. That opens the door to credential theft via `CryptAcquireContext` and `CryptExportKey`, or signals that it's safe to generate or steal user keys. It’s also a setup step for code signing abuse, where tools look for a valid CSP before calling `CryptSignHash`. And since it blends in with normal crypto usage, it’s great for defense evasion, whether you're siphoning certs, forging trust, or prepping for deeper API abuse down the line.

### 🛡️ Detection Opportunities  

### 🔹 YARA
Check out some sample YARA rules here: [CryptEnumProviders.yar](https://github.com/danafaye/WindowsAPIAbuseAtlas/blob/main/ADVAPI32/CryptEnumProviders/CryptEnumProviders.yar)

> **Heads up:** These rules are loosely scoped and designed for hunting and research. They're **not** meant for production detection systems that require low false positives. Please test and adjust them in your environment.

### 🔸 Behavioral Indicators
- **Recon & Staging** - Unusual provider enumeration by non-crypto apps. 
- Most software that uses CryptEnumProviders is tied to legit crypto workflows—browsers, certificate tools, system services. If you see enumeration coming from unexpected binaries (e.g. LOLBins, scripting hosts, temp-folder EXEs), start pulling that thread.

- Enumeration followed by process hollowing or injection - If a process calls CryptEnumProviders, then immediately spawns a child or injects into another process, that’s a suspicious chain—especially if the parent wasn’t known for touching CryptoAPI at all.

- **Credential Access** Enumeration preceding CryptoAPI key export or theft. Watch for CryptEnumProviders followed by calls to functions like CryptAcquireContext, CryptGetUserKey, or CryptExportKey. This pattern often shows up in credential dumping tools trying to siphon out user or system keys.

- **Legacy provider targeting** Some threat actors check for old CSPs (e.g., "Microsoft Base Cryptographic Provider v1.0") that are easier to break or misconfigure. Detection here means logging not just that enumeration happened, but which providers were queried—if your telemetry goes that deep.

- **Defense Evasion & Trust Abuse** Enumeration from unsigned binaries before code signing attempts
Some attackers use this API to find suitable providers for signing malicious payloads. If an unsigned binary enumerates CSPs, then starts using CryptSignHash or CertCreateSelfSignCertificate, that's an abuse path worth flagging.


### 🦠 Malware & Threat Actors Documented Abusing CryptEnumProviders

### **Ransomware**
 - CryptNet
 - Locky

### **Commodity Loaders & RATs**
 - AsyncRAT
 - BatLoader

### **APT & Threat Actor Toolkits**
 - Kimsuky APT
 - Scattered Spider

### **Red Team & Open Source Tools**
 - Empire

 > **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `CryptEnumProviders`.

### 📚 Resources  
- Microsoft Docs: [CryptEnumProviders](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptenumprovidersa)
- MITRE: [Unsecured Credentials: Private Keys](https://attack.mitre.org/techniques/T1552/004/)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main) 