# 🔗 WNetAddConnection2

## 🚀 Executive Summary
`WNetAddConnection2` is the Windows API that lets a process create a network connection to a remote resource, like a shared folder or a network printer. At first glance, it looks pretty harmless, after all, it's mostly just business as usual network stuff. But attackers and red teamers have learned it’s a fantastic way to pivot, exfiltrate data, or drop payloads onto other machines without triggering the usual alarms. If your network drives start disappearing into thin air, this API is probably involved somewhere.

## 🔍 What is WNetAddConnection2?
At its core, `WNetAddConnection2` is a wrapper around the Windows networking stack that lets a process map a remote resource to a local device. You tell it the remote path, provide credentials if necessary, and Windows handles the authentication and connection. It’s what underpins “map network drive” in File Explorer, and the API can even store credentials for reuse. To a normal admin or user, it’s just convenient. To a malware author, it’s a stealthy highway to move laterally and blend in.

> Note: Ah yes, the “2” at the end of `WNetAddConnection2` classic Windows API naming convention chaos. The “2” doesn’t mean it’s twice as powerful (sadly), it usually means Microsoft wanted a slightly tweaked version of an older function, often adding Unicode support, extra flags, or slightly different behavior. In this case, the original `WNetAddConnection` existed, but `WNetAddConnection2` is the one that actually sees the light of day in most modern code. For attackers, the “2” is irrelevant. It’s just the function that does the job, quietly mapping drives and bridging systems while defenders wonder why their network drives are suddenly adventurous.

## 🚩 Why It Matters
Why care about a network connection API? Because attackers don’t want to blow their cover. Using `WNetAddConnection2`, a piece of malware or a red team implant can reach across the network to other machines without spawning suspicious SMB traffic or brute forcing shares in the traditional sense. This API is also credential aware, meaning it can silently leverage existing credentials or prompt for them, making lateral movement, file staging, and exfiltration far smoother and quieter than shouting “hey everyone, I’m hacking!” across the network.

## 🧬 How Attackers Abuse It
Malware and offensive operators use `WNetAddConnection2` in a few flavors. Ransomware can use it to map drives on remote hosts and drop payloads before triggering encryption. RATs and commodity loaders may silently connect to network shares to download modules or exfiltrate data. In APT operations, it’s often paired with stolen credentials to quietly move through a corporate network like a ghost. And on the red team side, this API is practically a Swiss army knife: mapping a drive, copying tools, or testing credential access without creating a fuss. The beauty for them ... it’s legit API calls doing malicious work, which is exactly what makes detection tricky.

## 🛡️ Detection Opportunities
Like we've seen so many times before ... detecting `WNetAddConnection2` abuse is mostly about context. A standard user mapping `\\server\share` is fine. But when a rarely used process suddenly starts creating network connections to dozens of endpoints, especially with credentials, that’s suspicious. Correlate these calls with process creation events, unusual account usage, or network activity that looks like lateral movement. Look for non interactive processes suddenly storing credentials or mapping drives during odd hours. While this API itself doesn’t scream “malware,” the patterns around it do.

Here are some sample YARA rules to detect suspicious use of `WNetAddConnection2`:

See [WNetAddConnection2.yar](./WNetAddConnection2.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
Processes dynamically resolving `WNetAddConnection2` instead of linking it statically, particularly in unusual binaries. Non Windows signed or unexpected applications importing this API directly from `mpr.dll`. Attempts to map multiple remote shares in a short timeframe, especially across different hosts or credentials. Connections that correlate with file staging, exfiltration, or other post exploitation actions. Use of the API alongside stolen credentials, impersonated accounts, or privilege escalation behavior.

## 🦠 Malware & Threat Actors Documented Abusing WNetAddConnection2

### **Ransomware**
 - Locky
 - Petya & NotPetya

### **Commodity Loaders & RATs**
 - Kazuar
 - Emotet

### **APT & Threat Actor Toolkits**
 - APT32
 - APT29

### **Red Team & Open Source Tools**
 - RedTeam-Tools


> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `WNetAddConnection2`.

## 🧵 `WNetAddConnection2` and Friends
`WNetAddConnection2` often shows up alongside credential APIs like `LogonUser` or `ImpersonateLoggedOnUser`, file staging routines, and other network manipulation APIs such as NetUseAdd. Watching how these APIs chain together gives defenders a more complete picture of lateral movement and exfiltration patterns.

## 📚 Resources
- [Microsoft Docs: WNetAddConnection2](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection2a)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!