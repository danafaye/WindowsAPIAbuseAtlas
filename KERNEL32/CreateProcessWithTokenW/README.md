# 🪪 CreateProcessWithTokenW: The Fake ID

## 🚀 Executive Summary
`CreateProcessWithTokenW` is a powerful API that enables launching a process with a specified user token, often used to impersonate another user or elevate privileges. While this behavior is useful for legitimate administrative tasks, it is frequently abused by attackers to escalate privileges, bypass UAC, or move laterally with stolen tokens. Its misuse is common in malware, red team tools, and APT tradecraft. Understanding this API—and the patterns around its abuse—helps defenders recognize stealthy privilege transitions and detect attacks that rely on hijacking execution context.

## 🔍 What is CreateProcessWithTokenW?
`CreateProcessWithTokenW` serves as a critical component in Windows for managing process execution under specific security contexts. Its primary legitimate function is to launch a new process with an explicitly provided access token, rather than inheriting the token of the calling process. This capability is indispensable for secure applications, such as services that need to execute user-specific processes, or for applications requiring precise privilege delegation. By allowing a program to create a process that runs with the privileges of a different user or with a modified set of privileges, `CreateProcessWithTokenW` facilitates secure impersonation and compartmentalization, ensuring that operations are performed with the minimum necessary permissions.

## 🚩 Why It Matters
Understanding this API is crucial because its powerful capabilities for privilege management and execution context switching can be, and often are, co-opted for malicious purposes. Familiarity with its proper usage helps in distinguishing legitimate system behavior from attempts at privilege escalation, lateral movement, or stealthy execution, making it a key area for those analyzing system activity.

## 🧬 How Attackers Abuse It
 - **Token Theft**: Malware identifies a high-privilege process (via [EnumProcesses](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/KERNEL32/EnumProcesses) or [CreateToolhelp32Snapshot](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/KERNEL32/CreateToolhelp32Snapshot)), opens a handle (OpenProcess), then extracts and duplicates its access token using OpenProcessToken and DuplicateTokenEx.
 - **Elevated Execution**: With a stolen or duplicated elevated token, `CreateProcessWithTokenW` is invoked to spawn a new process (cmd.exe, rundll32.exe, or a malicious payload), now running under Administrator or SYSTEM.
 - **UAC Bypass**: Attackers may hijack auto-elevated tokens (from trusted processes like schtasks.exe or compmgmtlauncher.exe) to silently launch elevated processes without triggering a UAC prompt.
 - **Lateral Movement**: If an attacker obtains a domain token with administrative rights on remote hosts, they may combine `CreateProcessWithTokenW` with remote execution methods (DCOM, WMI, or PsExec-style behavior) to launch payloads across systems.
 - **Stealth**: The spawned process may mimic legitimate binaries (svchost.exe) and inherit security attributes from the stolen token, aiding in detection evasion and forensic obfuscation.

## 🛡️ Detection Opportunities
Here are some sample YARA rules to detect suspicious use of `CreateProcessWithTokenW`:

See [CreateProcessWithTokenW.yar](./CreateProcessWithTokenW.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - Privilege escalation from low-privileged processes: Unexpected cmd.exe, powershell.exe, or renamed binaries running as SYSTEM or Administrator.
 - Token manipulation chain: `OpenProcess` → `OpenProcessToken` → `DuplicateTokenEx` → `CreateProcessWithTokenW`, especially targeting lsass.exe, winlogon.exe, or services.exe.
 - Abnormal parent-child relationships: Scripting engines or non-elevated processes spawning elevated children.
 - Usage by non-standard binaries: Rare or unsigned executables importing or resolving `CreateProcessWithTokenW`.

#### Reverse Engineering Clues
 - Imports from advapi32.dll for token-related APIs.
 - Code scanning for elevated processes ([EnumProcesses](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/KERNEL32/EnumProcesses), [CreateToolhelp32Snapshot](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/KERNEL32/CreateToolhelp32Snapshot)).
 - Hardcoded elevation targets: cmd.exe, powershell.exe, or LOLBins like fodhelper.exe.
 - References to token privileges: `SeImpersonatePrivilege`, `LOGON32_LOGON_INTERACTIVE`, etc.

#### Defensive Strategies
 - Audit token operations: Monitor Event IDs 4624, 4672, 4688. Alert on unexpected token duplication or privilege usage.
 - Restrict impersonation privileges: Limit access to `SeImpersonatePrivilege` and `SeAssignPrimaryTokenPrivilege`.
 - Harden UAC: Disable auto-elevation where feasible.
 - EDR detection logic: Correlate token theft APIs with suspicious process creation.
 - Enable LSASS protection (RunAsPPL) to prevent SYSTEM token theft.

## 🦠 Malware & Threat Actors Documented Abusing CreateProcessWithTokenW

### **Ransomware**
 - Anubis
 - 8Base
 - DragonForce 

### **Commodity Loaders & RATs**
 - Bumblebee Loader
 - CosmicDuke
 - Warzone

### **APT & Threat Actor Toolkits**
 - APT28
 - Lazarus Group
 - SideWinder

### **Red Team & Open Source Tools**
 - Brute Ratel
 - Metasploit
 - PowerShell Empire

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `CreateProcessWithTokenW`.

## 🧵 `CreateProcessWithTokenW` and Friends
Several Windows APIs offer similar functionality to `CreateProcessWithTokenW`, enabling attackers to spawn new processes under different security contexts. `CreateProcessAsUserW` is functionally close and equally abusable, requiring slightly different privileges (`SeAssignPrimaryTokenPrivilege`). Internally, both may invoke `CreateProcessInternalW`, which handles much of the actual process creation logic. `CreateProcess` itself is the simpler variant, typically used without explicit token manipulation but still relevant in chains where the current process is already running in an elevated context. Together, these APIs form a family of process launch functions that, when paired with token theft or privilege manipulation, provide multiple avenues for stealthy privilege escalation and lateral movement.

## 📚 Resources
- [Microsoft Docs: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!