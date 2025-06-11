# 🛠️ UpdateProcThreadAttribute: The Hidden Lever Behind Process Injection

## 🚀 Executive Summary

`UpdateProcThreadAttribute` is a powerful Windows API that’s meant to give precise control over process and thread parameters during creation. But attackers abuse it to perform stealthy process injection, spoof parent processes for evasion, and bypass security tools by manipulating how new processes are initialized.

## 🔍 What is UpdateProcThreadAttribute?

`UpdateProcThreadAttribute` is part of the process creation API family in `kernel32.dll`. It lets you mess with things like parent PID, mitigation policies, and handle inheritance before a new process even starts. A legit feature, but malware loves it for spoofing process trees, dodging defenses, and slipping code into fresh processes without much noise.

## 🚩 Why It Matters

- **Parent process spoofing:** Attackers can make malicious processes appear as if they were spawned by trusted system processes (e.g., `explorer.exe`).
- **Process injection:** Used to inject code or DLLs into new processes at creation time. Especially in cases where attacks want to control how a process behaves before it even runs.
- **Security evasion:** Helps bypass security products that monitor standard process creation flows.

## 🧬 How Attackers Abuse It

- Prepare a `STARTUPINFOEX` structure with custom attributes.
- Use `UpdateProcThreadAttribute` to set the parent process, enable handle inheritance, or pass handles (for shared memory mappping)
- Call `CreateProcess` or `CreateProcessInternalW` with the modified structure to launch a process with the desired attributes.
- Achieve stealthy code execution, parent spoofing, or in-memory injection.  Usually with `WriteProcessMemory` or `CreateRemoteThread`

## 👀 Sample Behavior

### API Sequences
- `InitializeProcThreadAttributeList` → `UpdateProcThreadAttribute` → `CreateProcess` / `CreateProcessInternalW`
- Often followed by `ResumeThread` or `QueueUserAPC` in injection chains

### Parent Spoofing
- Parent process set to trusted binaries like `explorer.exe`, `svchost.exe`, or `lsass.exe`
- Child process appears benign in Task Manager, Sysmon logs, or EDR process trees

### Suspicious Attributes
- `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` used to set unexpected parent-child relationships
- `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` disables protections like DEP or CFG
- `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` used for stealthy handle inheritance

### Memory Artifacts (Post-Launch)
- Hollowed or unmapped executable sections in the child process
- Reflectively injected DLLs or shellcode (no backing file on disk)
- `RWX` (read-write-execute) memory regions present in the spawned process

### Command-Line or Process Traits
- Child process started in a suspended state (`CREATE_SUSPENDED`)
- Privilege level mismatch between parent and child (e.g., SYSTEM child, user-level parent)

## 🛡️ Detection Opportunities

### 🔹 YARA

Here are some sample YARA rules to detect suspicious use of `UpdateProcThreadAttribute`:

See [UpdateProcThreadAttribute.yar](./UpdateProcThreadAttribute.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🔹 Behavioral Indicators

- Unexpected or unusual use of `UpdateProcThreadAttribute` in user applications that don't or shouldn't mess with process attributes.
- Setting parent process to a high-privilege or system process to blend in or spoof.
- Combining `UpdateProcThreadAttribute` with injection APIs like `WriteProcessMemory`, `CreateRemoteThread`, or [NtQueueApcThread](../../NTDLL/NtQueueApcThread/README.MD).
- Fast, scripted sequence of attribute updates followed imediately by process creation and suspicious memory activity.

## 🦠 Malware & Threat Actors Documented Abusing UpdateProcThreadAttribute

Below is a curated list of malware families, threat actors, and offensive tools known to abuse or patch `UpdateProcThreadAttribute` for defense evasion.  

For the latest technical write-ups, search for the malware or tool name together with "UpdateProcThreadAttribute" on reputable security blogs, threat intelligence portals, or simply google. (Direct links are not included to reduce maintenance.)

### **Ransomware**
- BlackBasta
- DarkGate

### **Commodity Loaders & RATs**
- AsyncRAT
- Pure Crypter (loader)
- PureHVNC RAT
- Ursnif (Gozi)
- some cryptojacking malware

### **APT & Threat Actor Toolkits**
- APT41
- Lazarus
- Sandworm

### **Red Team & Open Source Tools**
- CobaltStrike
- likely others

> **Note:** This list isn’t exhaustive. Many modern malware families and offensive security tools use `UpdateProcThreadAttribute` for stealth and evasion.

## 🧵 `UpdateProcThreadAttribute` and Friends

`UpdateProcThreadAttribute` is often used alongside APIs like `CreateProcess`, `CreateProcessInternalW`, `InitializeProcThreadAttributeList`, and process injection techniques. Monitoring for these APIs in combination can help defenders spot advanced process manipulation and injection tactics.

## 📚 Resources

- [Microsoft Docs: UpdateProcThreadAttribute](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-updateprocthreadattribute)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!