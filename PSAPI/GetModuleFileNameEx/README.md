# 🛠️ GetModuleFileNameEx: 

## 🚀 Executive Summary
`GetModuleFileNameEx` gives a process the power to peek at another process’s loaded modules and retrieve the file path of a specific module (including the main executable). While often used legitimately for diagnostics, debugging, and inventory purposes, in the wrong hands it becomes a reconnaissance tool. It's a way for malware to fingerprint its environment, identify security software, and adapt its behavior to evade detection.

## 🔍 What is GetModuleFileNameEx?
A Win32 API call from Psapi.dll, `GetModuleFileNameEx` retrieves the fully qualified path for a module loaded into another process. You provide a handle to the target process and a handle (or NULL) for the module of interest, and it returns the path. If the module handle is NULL, it returns the path to the process’s executable image. This API requires `PROCESS_QUERY_INFORMATION` and `PROCESS_VM_READ` permissions on the target process.

## 🚩 Why It Matters
From a defensive standpoint, any API that lets one process read metadata from another process should raise eyebrows. The file path to a running process is a treasure map for an attacker. It can reveal security tools, sandbox locations, monitoring agents, or custom built protections. This is particularly useful for malware looking to:

- Detect if it’s running in a sandbox (like C:\sandbox\...)
- Identify security products to disable or evade
- Tailor payload delivery based on environment

## 🧬 How Attackers Abuse It
Attackers rarely call `GetModuleFileNameEx` in isolation. It’s usually part of a reconnaissance chain that begins with process enumeration via APIs like `EnumProcesses` or `CreateToolhelp32Snapshot`. Once they have a list of process IDs, the malware opens each one and retrieves the full path of its main executable (or other loaded modules) using `GetModuleFileNameEx`. This gives the attacker precise knowledge of what’s running, where it lives on disk, and whether the environment contains telltale signs of a sandbox, virtual machine, or analysis tool. By comparing retrieved paths against embedded allowlists or blocklists, the malware can decide whether to execute, go dormant, or alter its behavior.

This information isn’t just for stealth. It’s also a targeting tool. A ransomware sample might search for paths containing EDR or AV agents and terminate them before encryption. A RAT could identify high value processes for code injection, or avoid injecting into processes monitored by security tools. In some cases, collected process paths are sent back to a command and control server, giving operators a near real time inventory of the compromised host. Whether for evasion, privilege escalation, or precision targeting, `GetModuleFileNameEx` serves as an efficient bridge between basic process enumeration and informed malicious action.

## 🛡️ Detection Opportunities
Look for suspicious patterns where `GetModuleFileNameEx` is called in processes that:

- Don’t typically perform system wide process inspection (like Office macros, web browsers)
- Enumerate processes immediately before or after the call
- Run shortly after initial access or payload execution
- Access processes belonging to security tools or system utilities

Event tracing with ETW providers like Microsoft Windows Threat Intelligence or hooking `GetModuleFileNameEx` in an EDR sandbox can flag anomalous usage.

Here are some sample YARA rules to detect suspicious use of `GetModuleFileNameEx`:

See [GetModuleFileNameEx.yar](./GetModuleFileNameEx.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
- Enumeration of processes followed by module file path retrieval
- Process path checks against hardcoded blocklists or allowlists
- Conditional branching in code based on retrieved module paths
- Collection of file paths for exfiltration
- Attempts to open handles to high value processes

## 🦠 Malware & Threat Actors Documented Abusing GetModuleFileNameEx

### **Ransomware**
- Conti
- LockBit

### **Commodity Loaders & RATs**
- Agent Tesla
- Remcos RAT

### **APT & Threat Actor Toolkits**
- APT29 

### **Red Team & Open Source Tools**
- Cobalt Strike
- Metasploit

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `GetModuleFileNameEx`.

## 🧵 `GetModuleFileNameEx` and Friends
`GetModuleFileNameEx` lives in a small but potent family of APIs designed to reveal what’s loaded inside a process and where it lives on disk. Close cousins include `GetModuleBaseName`, which trims the output down to just the module’s filename without the path, and `GetModuleFileName`, which serves the same purpose but only for modules in the calling process. Other related calls, like `QueryFullProcessImageName`, can return the executable’s absolute path without the need for enumerating modules first. Attackers may also reach for `K32GetModuleFileNameEx` (the kernel32 wrapper) for broader compatibility across Windows versions.

From a detection standpoint, these APIs form overlapping capability zones; if one is blocked, an adversary can often pivot to another with minimal code changes. This functional redundancy is exactly why defenders need to consider the entire class of “process image path retrieval” APIs rather than just hunting for a single call. Whether it’s `GetModuleFileNameEx` pulling the full path, `GetModuleBaseName` grabbing just the name, or `QueryFullProcessImageName` bypassing module handles entirely, the end result is the same: attackers gain a clear view of what’s running and where, setting the stage for informed targeting or evasion.

## 📚 Resources
 - [Microsoft Docs: GetModuleFileNameEx](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmodulefilenameexa)
 - [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!