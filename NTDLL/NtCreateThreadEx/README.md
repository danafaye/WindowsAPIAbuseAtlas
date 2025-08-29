# 🧵 NtCreateThreadEx 

## 🚀 Executive Summary
`NtCreateThreadEx` is one of those “behind the curtain” Windows APIs that malware authors and red teamers just love. While higher level functions like `CreateRemoteThread` get most of the documentation, `NtCreateThreadEx` sits underneath, offering the same thread creation powers but with more control and fewer eyes watching. This makes it a go to choice for process injection, stealthy execution, and all the usual shenanigans attackers pull when they want to run their code inside another process.

## 🔍 What is NtCreateThreadEx?
At its core, `NtCreateThreadEx` is a system call exposed by `ntdll.dll`. It isn’t officially documented by Microsoft, which gives it a bit of an “underground” feel. But that doesn’t mean it’s obscure on the contrary, attackers and researchers have studied it thoroughly.

Think of it like this: when you want to create a new thread in Windows, you can use the nice, shiny `CreateRemoteThread` API that Microsoft tells you about. Or, if you want to bypass some of the security hooks and have a little more low level control, you can go straight to `NtCreateThreadEx`. That’s why it shows up so often in offensive tools and malware families.

## 🚩 Why It Matters
The reason this API matters is pretty simple: it’s at the heart of so many injection techniques. If you want to run your payload inside another process, you need a way to kick off execution. `NtCreateThreadEx` does exactly that, but it does so in a way that avoids some of the tripwires defenders have set on higher level APIs.

Attackers like it because it gives them stealth and flexibility. Defenders care because when you see `NtCreateThreadEx` being called into sensitive processes like `LSASS` for credential theft; it’s usually a red flag. And since it’s not a high level, well documented API, monitoring for it requires a bit more effort.

## 🧬 How Attackers Abuse It
The classic abuse pattern is pretty much the same as every injection chain you’ve ever read about. First, the attacker gets a handle to the target process. Then they carve out some memory inside it (using functions like `VirtualAllocEx` or `NtAllocateVirtualMemory`), write their malicious code into that memory (`WriteProcessMemory` or `NtWriteVirtualMemory`), and finally, they need to run it. That’s where `NtCreateThreadEx` comes in. It creates a new thread in the remote process and points it at the attacker’s payload.

You’ll see this exact pattern pop up in process hollowing, reflective DLL injection, and plenty of custom injection tricks. It’s flexible, reliable, and widely supported, which explains why it shows up again and again in both real world malware and penetration testing frameworks.

## 🛡️ Detection Opportunities
 - Look for calls to `NtCreateThreadEx` targeting processes like `lsass.exe`, `winlogon.exe`, or security-related processes.
 - Flag sequences where `NtAllocateVirtualMemory` → `NtWriteVirtualMemory` → `NtCreateThreadEx` happen close together.
 - Pay attention to threads being created in processes that don’t normally load third party code (svchost.exe).
 - Monitor for thread creation where the start address points to suspicious or newly allocated memory regions.
 - Use telemetry sources like Sysmon (Event ID 8) or ETW to catch unusual remote thread creation events.

Here are some sample YARA rules to detect suspicious use of `NtCreateThreadEx`:

See [NtCreateThreadEx.yar](./NtCreateThreadEx.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
What usually gives away `NtCreateThreadEx` abuse is the context. A thread being created in a process that normally has no business running user code, or seeing it show up right after memory was allocated and written to, are the telltale signs. When attackers try to be stealthy, these subtle patterns are often the best breadcrumbs defenders have to follow.

## 🦠 Malware & Threat Actors Documented Abusing NtCreateThreadEx

### **Ransomware**
 - BabLock
 - BlackMatter
 - NetWalker

### **Commodity Loaders & RATs**
 - Cherry Loader
 - Remcos RAT
 - QakBot

### **APT & Threat Actor Toolkits**
 - APT32
 - APT41
 - Lazarus

### **Red Team & Open Source Tools**
 - Havoc C2
 - Metasploit
 - Sliver
 
> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `NtCreateThreadEx`.

## 🧵 `NtCreateThreadEx` and Friends
`NtCreateThreadEx` rarely works alone. It usually shows up with friends like `CreateRemoteThread` (the more documented cousin), `RtlCreateUserThread` (an alternative thread-creation routine), and `NtResumeThread` (to actually start execution on suspended threads). You’ll also see it paired with `SetThreadContext`, which attackers use to hijack existing threads instead of creating new ones. Together, these APIs make up the toolbox for anyone looking to manipulate threads for fun or profit.

## 📚 Resources
- [ntdoc.m417z.com: NtCreateThreadEx](https://ntdoc.m417z.com/ntcreatethreadex)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!