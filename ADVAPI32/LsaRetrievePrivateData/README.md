# 🔐 LsaRetrievePrivateData

## 🧠 Executive Summary  
`LsaRetrievePrivateData` is a high-value target in `advapi32.dll` that lets callers extract secrets stored in the Local Security Authority (LSA). Originally designed to support secure credential storage, it’s now a post-exploitation favorite for attackers digging up service account passwords, VPN creds, and other juicy config secrets.

## 🔍 What is `LsaRetrievePrivateData`?  
`LsaRetrievePrivateData` is a Windows API that lets callers retrieve secret blobs stored in the Local Security Authority (LSA) under custom key names. These "private data" entries are encrypted at rest, but if you’ve got the right privileges, this function hands over the decrypted plaintext.

This can include things like:
 - IIS App Pool and Virtual Directory passwords
 - Auto-logon credentials
 - Service account secrets
 - Credentials stashed by legacy or misconfigured apps

 > **Note:** LSA secrets aren’t exposed through standard registry APIs. While they are stored under the `SECURITY` hive, each entry is encrypted and only accessible by name through specific LSA APIs like `LsaRetrievePrivateData`. You won’t find them with tools like `reg query` or `RegQueryValueEx`.

## 📌 Why it Matters  
- **Credential Access**: attackers use it to dump stored service credentials, VPN secrets, or application keys.  
- **Persistence Enablement**: secrets pulled here can enable lateral movement, privilege escalation, or long-term footholds.  
- **Living Off the Land**: no need to drop tools; just use built-in Windows capabilities to quietly extract secrets.

## ⚔️ How Attackers Abuse It  
Once SYSTEM-level access is achieved, malware or red teamers open a policy handle via `LsaOpenPolicy` and call `LsaRetrievePrivateData` with a key name like `"SCPassword"` or custom app values. This lets them exfiltrate plaintext secrets that were stored programmatically by services, third-party tools, or misconfigured GPOs.

To call it, you first open a handle to the LSA Policy object using `LsaOpenPolicy`, requesting `POLICY_GET_PRIVATE_INFORMATION` rights. That usually means you’re running as `SYSTEM` or have elevated privileges, normal users won’t cut it.

Most apps import `LsaRetrievePrivateData` from `advapi32.dll`, though it ultimately routes through `secur32.dll` and internal LSA mechanisms, ending in `lsass.exe`. That indirection makes it harder to detect unless defenders are logging LSA subsystem activity at the `syscall` or RPC level.

In red team and malware usage, it’s prized for credential harvesting; quietly pulling secrets like service account and app pool passwords already stored by the system. Beyond reuse, it gives attackers a peek into how credentials are handled, stored, and protected across the environment.

## 🧪 Sample Behavior  
1. Call `LsaOpenPolicy` with `POLICY_GET_PRIVATE_INFORMATION`.  
2. Use `LsaRetrievePrivateData` with a known or brute-forced key name.  
3. Capture and decode the resulting secret data.

No injection, no dropped tools ... just native API calls and plaintext secrets.

## 🛡️ Detection Opportunities

**What to watch for**:  
- `LsaOpenPolicy` followed by `LsaRetrievePrivateData` in `SYSTEM` context  
- Unexpected access from non-service processes  
- Unusual or excessive queries for secret names

**What to capture**:  
- Source process and command-line arguments  
- User context (SYSTEM, administrator, service)  
- Queried key names  
- Network context if the process is remote-capable

## 🦠 Malware & Threat Actors Documented Abusing LsaRetrievePrivateData

### Ransomware  
- Ryuk  
- BlackMatter  

### Red Team & Open Source Tools  
- Mimikatz (`lsadump::secrets`)  
- Custom C# tooling in offensive frameworks

> **Note:** It’s often used post-exploitation, meaning detections require privilege escalation context and sensitive logging.

## 🧵 `LsaRetrievePrivateData` and Friends  
This API often appears alongside `LsaStorePrivateData` and `LsaOpenPolicy`. While not as noisy as credential dumping tools, it’s a quieter cousin used to extract secrets when attackers want to avoid triggering AV with Mimikatz.

## 📚 Resources  
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)  
- [Microsoft Docs — LsaRetrievePrivateData](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaretrieveprivatedata)  
- [Mimikatz Documentation](https://github.com/gentilkiwi/mimikatz)
