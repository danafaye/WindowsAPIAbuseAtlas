# 🫥 CreateProcessAsUserW: Token-powered stealth execution

## 🚀 Executive Summary
`CreateProcessAsUserW` lets a process launch another process under a different user token. It is typically used to spawn a child with different privileges. While it’s critical for legitimate applications like task schedulers or remote management tools, it’s also a popular choice for attackers looking to pivot laterally, evade controls, or execute payloads under stolen credentials.

## 🔍 What is CreateProcessAsUserW?
A Win32 API function that creates a new process in the security context of a specified user. It’s often used after a successful `LogonUser` or `DuplicateTokenEx`, and requires the `SeAssignPrimaryTokenPrivilege` and `SeIncreaseQuotaPrivilege` privileges. Found in `advapi32.dll`.

## 🚩 Why It Matters
This API is highly valued in offensive workflows for privilege separation, evasion, and stealthy execution. When an attacker gains valid credentials or tokens, `CreateProcessAsUserW` lets them act as another user; often one with higher privileges without triggering user facing UI prompts or typical execution paths.

## 🧬 How Attackers Abuse It
Attackers commonly pair this API with stolen credentials or impersonation tokens to spawn privileged processes. This is especially useful in:
 - Lateral movement scenarios
 - Bypassing application whitelisting
 - Launching processes that inherit a less suspicious context (SYSTEM or an admin)

Common abuse flows:
 - LogonUserW ➝ DuplicateTokenEx ➝ CreateProcessAsUserW
 - Token theft via OpenProcessToken ➝ impersonation ➝ spawn payload

## 🛡️ Detection Opportunities
Look for uncommon parent/child process pairs involving `CreateProcessAsUserW`. Unusual spawning patterns; for example `svchost.exe` or a scheduled task spawning `cmd.exe` or `powershell.exe`. These may indicate abuse.

Correlate with prior token manipulation or logon activity. High-value detections include:

 - Processes with unusual tokens launching CLI utilities
 - Processes inheriting tokens from disjointed logon sessions
 - Abnormal privilege use (`SeAssignPrimaryTokenPrivilege` in non-standard binaries)

Here are some sample YARA rules to detect suspicious use of `CreateProcessAsUserW`:

See [CreateProcessAsUserW.yar](./CreateProcessAsUser.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - Unexpected process launches from service hosts, task schedulers, or other SYSTEM context processes
 - Use of `CreateProcessAsUserW` shortly after `LogonUserW` or token duplication
 - Spawning of unsigned or LOLBIN-based processes under a stolen token
 - New processes running in session 0 with mismatched parent/child logon sessions

## 🦠 Malware & Threat Actors Documented Abusing CreateProcessAsUserW

### **Ransomw
 - Ryuk
 - Conti

### **Commodity Loaders & RATs**
 - IcedID
 - Remocs

### **APT & Threat Actor Toolkits**
 - APT29
 - FIN7

### **Red Team & Open Source Tools**
 - Mimikatz
 - Mythic
 - Sliver

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `CreateProcessAsUserW`.

## 🧵 `CreateProcessAsUserW` and Friends
`CreateProcessAsUserW` is frequently used alongside several other token related APIs. `LogonUserW` is often the first step, used to obtain a handle to another user’s security token. This is typically followed by `DuplicateTokenEx`, which creates a primary token suitable for process creation. `ImpersonateLoggedOnUser` may be used to temporarily shift context prior to launching a process, while `SetTokenInformation` can modify session or group attributes on the token itself. In remote desktop scenarios, `WTSQueryUserToken` is a common method for obtaining a token tied to an active terminal session. Another close cousin, `CreateProcessWithTokenW`, offers similar functionality but comes with additional restrictions. Together, this set of APIs forms a robust privilege and execution stack equally useful in enterprise grade systems management and in adversary post exploitation chains.

## 📚 Resources
- [Microsoft Docs: CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!