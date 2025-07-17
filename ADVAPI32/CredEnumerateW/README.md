# 🔐 CredEnumerateW: Lootable Credentials

## 🚀 Executive Summary
`CredEnumerateW` offers attackers a rare combination of signal rich output and low friction access. It doesn’t require privilege escalation, doesn’t pop user prompts, and doesn’t break when EDRs clamp down on memory scraping. Instead, it delivers credential artifacts on demand cleanly, quietly, and with the full blessing of the Windows API surface. For adversaries, it’s a low risk, high reward entry point into credential access that sidesteps many of the noise heavy pitfalls associated with LSASS dumping or keylogging. As more defenders harden traditional choke points, this API is increasingly weaponized not just for looting secrets, but for gaining initial access to footholds, VPNs, RDP endpoints, and cloud accounts using what the victim's machine has already stashed away.

## 🔍 What is CredEnumerateW?
When apps need to recall what the user told Windows to remember, they reach for `CredEnumerateW`. Remote desktop clients use it to pull saved logins. SSO agents tap it to gather credentials quietly in the background. Even scheduled tasks or service accounts might use it to rehydrate access after reboot. It’s the sanctioned way to list stored secrets scoped to the current security context. Whatever the process has permission to see, it can ask for by name or wildcard. No prompts. No UIs. Just a clean inventory of what’s already stashed.

`CredEnumerateW` is part of the **Credential Manager API** and retrieves an array of credentials matching a given filter. The function returns a pointer to an array of `PCREDENTIALW` structures, each representing a stored credential.

```
BOOL CredEnumerateW(
  LPCWSTR      Filter,
  DWORD        Flags,
  DWORD        *Count,
  PCREDENTIALW **Credential
);
```

When called without a filter (Filter = NULL), it returns all stored credentials visible to the current user context. It's a goldmine for attackers operating in a user session.

## 🚩 Why It Matters
Attackers lean on `CredEnumerateW` to quietly sweep through stored credentials, harvesting secrets that the user or system has saved over time. Because it returns a broad inventory without triggering alerts or user interaction, malware and red teams alike use it to map out what’s accessible, often as a first step before deeper credential theft or lateral movement. It’s a stealthy grab that blends into normal system behavior, making it a favored tool for sneaky reconnaissance inside Windows environments.

## 🧬 How Attackers Abuse It
Adversaries who gain a foothold in a system via phishing, malicious documents, or remote access tools, can call `CredEnumerateW` to harvest locally stored secrets without needing escalation or kernel access.

Malicious tooling uses this API to extract:

 - Cleartext passwords
 - Stored RDP credentials
 - VPN secrets
 - Outlook and browser credentials (if stored via Windows Credential Manager)

## 🛡️ Detection Opportunities
Here are some sample YARA rules to detect suspicious use of `CredEnumerateW`:

See [CredEnumerateW.yar](./CredEnumerateW.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - Monitor for processes (especially non-browser or non-shell) invoking `CredEnumerateW`.
 - Look for suspicious child processes spawned from office apps or LOLBins (rundll32, mshta) making Credential Manager API calls.
 - ETW and Sysmon with command-line logging may catch patterns of enumeration.

## 🦠 Malware & Threat Actors Documented Abusing CredEnumerateW

### **Ransomware**
 - Nyetya
 - Petya

### **Commodity Loaders & RATs**
 - Lamberts
 - RedLine
 - Vidar

### **APT & Threat Actor Toolkits**
 - APT31
 - APT32
 - Longhorn

### **Red Team & Open Source Tools**
 - Empire
 - SLaZagne
 - Mimikatz

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `CredEnumerateW` for stealth and evasion.

## 🧵 `CredEnumerateW` and Friends
While `CredEnumerateW` is commonly used to list stored credentials from the **Windows Credential Manager**, several sibling APIs expose related functionality that can similarly be abused to extract or manipulate user secrets. CredReadW allows adversaries to retrieve the full contents of a specific credential entry by name—often used after enumeration to pull plaintext passwords or binary secrets. `CredWriteW` and `CredDeleteW` permit attackers to modify or remove entries, potentially enabling persistence or cleanup. Additionally, `CredBackupCredentials` and `CredRestoreCredentials` can be leveraged to exfiltrate and later reinstate credential sets across systems. When used together, these APIs provide adversaries with a quiet and credential aware toolkit for harvesting secrets, planting footholds, or staging credential reuse all while operating under the guise of legitimate Windows functionality.

## 📚 Resources
- [Microsoft Docs: CredEnumerateW](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credenumeratew)
- [MITRE ATT&CK: Credential Access](https://attack.mitre.org/tactics/TA0006/)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!