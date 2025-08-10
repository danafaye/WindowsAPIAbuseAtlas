# 🪙 OpenProcessToken: Identity Theft

## 🚀 Executive Summary
`OpenProcessToken` is the doorman to Windows access tokens. The key objects that define a process’s security context. Once a handle is obtained, an attacker can impersonate a user, escalate privileges, or perform actions as another security principal. On its own, it might look like a benign API call… but paired with the right friends, it becomes a powerful part of the privilege escalation and impersonation toolchain.

## 🔍 What is OpenProcessToken?
`OpenProcessToken` is a Win32 API that retrieves a handle to the access token associated with a process. Access tokens store the security identity and privileges of a process or thread, and having a valid handle is the first step toward manipulating those privileges. This function is often paired with APIs like `[AdjustTokenPrivileges](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/ADVAPI32/AdjustTokenPrivileges)`, `DuplicateToken`, or `ImpersonateLoggedOnUser`.

## 🚩 Why It Matters
Access tokens are the currency of identity in Windows. If an attacker can open a token for a privileged process (like `winlogon.exe` or a SYSTEM owned service), they can potentially elevate their own privileges or pivot to new accounts entirely. Abuse of `OpenProcessToken` frequently appears in privilege escalation, credential theft, and lateral movement scenarios.

## 🧬 How Attackers Abuse It
Attackers use `OpenProcessToken` to grab handles to tokens belonging to high privilege processes. Once acquired, those tokens can be duplicated or adjusted to impersonate SYSTEM or domain admins, bypassing normal authentication. Malware often chains this with `LookupPrivilegeValue` and `[AdjustTokenPrivileges](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/ADVAPI32/AdjustTokenPrivileges)` to enable privileges like `SeDebugPrivilege`, opening the door to more intrusive actions.

## 🛡️ Detection Opportunities
 - **API Monitoring**: Alert on processes calling `OpenProcessToken` followed closely by token manipulation functions (`[AdjustTokenPrivileges](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/ADVAPI32/AdjustTokenPrivileges)`, `DuplicateTokenEx`, `SetThreadToken`).
 - **Token Handle Targeting**: Identify attempts to open tokens for critical processes such as `winlogon.exe`, `lsass.exe`, or service host processes running as SYSTEM.
 - **Behavioral Correlation**: Combine token handle access with subsequent suspicious actions. Like spawning processes with higher privileges to reduce false positives.

Here are some sample YARA rules to detect suspicious use of `OpenProcessToken`:

See [OpenProcessToken.yar](./OpenProcessToken.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - Process opens token of another process with higher privileges
 - Follow on calls to `[AdjustTokenPrivileges](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/ADVAPI32/AdjustTokenPrivileges)` or `DuplicateToken` within the same execution flow
 - Privilege escalation without interactive login
 - Creation of new processes running as SYSTEM or another user without normal authentication events

## 🦠 Malware & Threat Actors Documented Abusing OpenProcessToken

### **Ransomware**
 - LockBit
 - Ryuk

### **Commodity Loaders & RATs**
 - KillDisk
 - Pulsar RAT

### **APT & Threat Actor Toolkits**
 - APT29
 - FIN7

### **Red Team & Open Source Tools**
 - Cobalt Strike
 - Metasploit

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `OpenProcessToken`.

## 🧵 `OpenProcessToken` and Friends
`OpenProcessToken` rarely works alone. It’s often seen alongside a familiar crew of token handling APIs. `[AdjustTokenPrivileges](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/ADVAPI32/AdjustTokenPrivileges)` changes the privileges within a token, enabling capabilities like `SeDebugPrivilege`. `DuplicateToken` and `DuplicateTokenEx` create copies of tokens, setting the stage for impersonation. `SetThreadToken` applies a token to a specific thread, while `ImpersonateLoggedOnUser` fully assumes the identity represented by that token. And when the focus shifts from processes to threads, `OpenThreadToken` retrieves the token for a specific thread, giving attackers or administrators fine-grained control over security contexts.

## 📚 Resources
- [Microsoft Docs: OpenProcessToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!