# 🗝️ NtOpenProcessToken

## 🚀 Executive Summary
`NtOpenProcessToken` is the tiny door knocker that hands you a process’ security token. It’s boring and administrative until it isn’t: legitimately used by debuggers, privileged tooling, and some service management code, but also a shortcut for attackers who want to steal or impersonate credentials, escalate privileges, or build forged tokens for lateral movement. In practice the call is a neat early signal; watch who asks for which token, from where, and what they do with it next.

## 🔍 What is NtOpenProcessToken?
`NtOpenProcessToken` is a native NT API that, given a process handle, returns a handle to that process’ access token (subject to access checks). It exposes the kernel visible bridge to session, privilege, and ownership data, like SIDs, groups, privileges, and impersonation levels live in that token. User-mode wrappers exist, but the native syscall is where defenders can see direct intent: which token was requested, with what access (`TOKEN_QUERY` vs `TOKEN_DUPLICATE` vs `TOKEN_ADJUST_PRIVILEGES`), and whether the caller plans to impersonate, duplicate, or modify the token.

## 🚩 Why It Matters
Tokens are the currency of Windows privilege. A token gives you the identity and rights the kernel enforces; a duplicated or impersonated token gives you someone else’s authority. `NtOpenProcessToken` is frequently the precursor to dangerous stuff: duplicate and impersonate chains for lateral movement, privilege elevation via `SeDebugPrivilege` or token theft, and stealthy persistence when an implant uses a service account token instead of its own. The call itself is short and unglamorous; its consequences are not.

## 🧬 How Attackers Abuse It
Attackers use `NtOpenProcessToken` as the literal key grab: get a handle to a privileged process (LSASS, a service host, SYSTEM owned helper), open its token, and then do something useful with that identity. That “something useful” is predictable: duplicate the token (so it can be impersonated or used to spawn a new process), adjust privileges (add `SeDebug`/`SeImpersonate`), or assign the token to a thread to run actions under the victim identity. Tooling ranges from quick-and-dirty scripts that call

`OpenProcess` → `NtOpenProcessToken` → `DuplicateTokenEx`
 
 to polished implants that resolve native exports or use direct syscalls to avoid user mode hooks. The aim isn’t elegance; it’s authority: run as the service, touch files, create services, or move laterally without prompting for credentials.

## 🛡️ Detection Opportunities
Don’t alert on the API name; alert on the story. Capture token access masks (`TOKEN_DUPLICATE`, `TOKEN_ASSIGN_PRIMARY`, `TOKEN_ADJUST_PRIVILEGES`) and correlate them with who acquired the source process handle and what happened next. High-fidelity triggers are:

- Non admin processes opening tokens from LSASS/service hosts
- Immediate duplication or impersonation after a token-open
- Handles created with `PROCESS_ALL_ACCESS` by unexpected parents
- Direct syscall patterns that lack normal user mode breadcrumbs

Instrument the sequence:

 - `OpenProcess`/`ZwOpenProcess` → `NtOpenProcessToken` → `NtDuplicateObject`/`DuplicateTokenEx` → `SetThreadToken`/`CreateProcessWithTokenW` 

And build hunts that look for short lived helpers whose only job is token ops. Like always context is extremely important, so consider parent, signing, scheduled-job lineage, and subsequent process creation. These things are what turn an API call into a triageable incident.

Here are some sample YARA rules to detect suspicious use of `NtOpenProcessToken`:

See [NtOpenProcessToken.yar](./NtOpenProcessToken.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
Think in terms of what the token lets someone do, not just that it was opened. Watch for short lived helper processes that exist only long enough to grab a token and vanish. They often spawn something bigger with the stolen identity and never show up in change-control. 

- **Flag token use that crosses expected boundaries**: a token from an interactive user used to access SYSTEM-only resources, a service token used to initiate outbound SMB/auth to other hosts, or a token that spawns a process in a different session than the original owner
- **Look for mismatches between token metadata and activity**: logon type, session ID, or impersonation level that doesn’t fit the caller’s role
- **Sudden privilege changes immediately after a token operation**: `SeDebug`/`SeTakeOwnership` appearing in the process token then being used to change ACLs or install services
- **Tokens that are duplicated and then used to create new service processes**: scheduled tasks, or remotely injected threads are high signal, as are tokens handed off between processes (handle duplication/duplication via RPC) where the recipient normally wouldn’t need elevated rights
- **Treat repeated or scripted patterns as suspicious**: Repeated token opens against LSASS or service hosts across many endpoints in a short time window, or a cascade of helpers that each grab and pass along tokens, usually means an automated privilege theft pipeline rather than a one off admin action.

## 🦠 Malware & Threat Actors Documented Abusing NtOpenProcessToken

### **Ransomware**
- AlphV
- Black Basta
- LockBit

### **Commodity Loaders & RATs**
- AsyncRat
- GootKit
- Mekotio

### **APT & Threat Actor Toolkits**
- Equation Group
- Lotus Blossom
- Winnti

### **Red Team & Open Source Tools**
- Metasploit
- PowerSploit
- SharpSploit

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `NtOpenProcessToken`.

## 🧵 `NtOpenProcessToken` and Friends
Token operations never travel alone. Key siblings to watch together are `OpenProcess`/`ZwOpenProcess` for handle acquisition, `NtDuplicateObject` and `DuplicateTokenEx` for cloning tokens, `SetThreadToken`/`ImpersonateLoggedOnUser` and `NtSetInformationThread` for impersonation, `CreateProcessWithTokenW` for spawning under another identity, and credential dumpers and `SeDebugPrivilege` related APIs. Correlate token opens with subsequent process creation, service changes, and privilege adjustments to build a coherent story.

## 📚 Resources
- [Microsoft Docs: NtOpenProcessToken](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenprocesstoken)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!