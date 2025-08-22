# 📍ZwUnmapViewOfSection

## 🚀 Executive Summary
`ZwUnmapViewOfSection` is a low level native API exported by ntdll.dll that unmaps a previously mapped section from a process’s virtual address space. While it has legitimate use cases in memory management and resource cleanup, attackers frequently abuse it as part of process hollowing and code injection techniques. By unmapping legitimate code from a target process and replacing it with malicious code, adversaries gain stealthy execution that blends into trusted processes.

## 🔍 What is ZwUnmapViewOfSection?
At its core, this API is a thin wrapper around a system service in the Windows kernel. It takes a handle to a process and a base address, and then removes the mapped section from that address space. While developers may use it in scenarios such as cleaning up mapped files or managing shared memory, in practice it is far more notorious for its role in offensive tradecraft. Because it is exported by ntdll.dll, it often avoids user mode hooks placed on higher level APIs like those in kernel32.dll, making its use slightly stealthier.

## 🚩 Why It Matters
This API is central to attacks where adversaries want to replace legitimate code with malicious payloads. When combined with `CreateProcess` in suspended mode, an attacker can start a benign executable, strip out its original code with `ZwUnmapViewOfSection`, inject their malicious payload, and then resume execution. To defenders, this means the process on disk looks benign, but the code running in memory tells a very different story. Such techniques bypass naive detection methods that only look at binaries on disk.

## 🧬 How Attackers Abuse It
The most common abuse pattern is **process hollowing**. A malware family will create a suspended process, unmap its executable image using `ZwUnmapViewOfSection`, write in the malicious payload with `NtWriteVirtualMemory`, and then resume execution with `NtResumeThread`. The result is a trusted process name in Task Manager that is in fact executing attacker controlled code. This API is also leveraged in process replacement attacks, where a malicious payload completely overwrites the memory of a legitimate application. Because the call sits lower in the API stack, its use is less likely to be intercepted by user mode EDR hooks, which is why attackers continue to favor it.

## 🛡️ Detection Opportunities
Detection often comes down to recognizing the sequence of events rather than the API call in isolation. The creation of a suspended process followed quickly by a call to `ZwUnmapViewOfSection` is a strong signal of potential hollowing. Correlating this with subsequent memory writes into that process and the eventual resumption of its primary thread can provide high-fidelity detection. Attempts to unmap memory in sensitive processes such as lsass.exe or commonly abused living off the land binaries should also raise suspicion. ETW based telemetry, Sysmon eventing, or kernel level monitoring can all help in surfacing this behavior.

Here are some sample YARA rules to detect suspicious use of `ZwUnmapViewOfSection`:

See [ZwUnmapViewOfSection.yar](./ZwUnmapViewOfSection.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
Practical ways to spot malicious use of `ZwUnmapViewOfSection` include:

 - **Look for process hollowing chains**: A process is created in suspended mode, quickly followed by `ZwUnmapViewOfSection`, memory writes (`NtWriteVirtualMemory`), and then thread resumption (`NtResumeThread`).
 - **Flag unusual targets**: Unmapping sections inside high value processes like `lsass.exe`, `explorer.exe`, or security/EDR tools is rarely legitimate.
 - **Correlate with injection APIs**: Combine sightings of `ZwUnmapViewOfSection` with APIs such as `NtCreateSection`, `NtMapViewOfSection`, or `QueueUserAPC` to catch full injection workflows.
 - **Watch for timing anomalies**: Legitimate use usually happens during resource cleanup or application exit. Early unmapping in a newly spawned process often signals abuse.
 - **Baseline normal activity**: Profile which applications in your environment legitimately call `ZwUnmapViewOfSection` so deviations stand out.

## 🦠 Malware & Threat Actors Documented Abusing ZwUnmapViewOfSection

### **Ransomware**
- Hancitor
- Mailto
- SystemBC

### **Commodity Loaders & RATs**
- Emotet
- GUloader
- TrickBot

### **APT & Threat Actor Toolkits**
- APT28
- APT33
- Lazarus

### **Red Team & Open Source Tools**
- Cobal Strike
- Metasploit
- PowerShell Empire

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `ZwUnmapViewOfSection`.

## 🧵 `ZwUnmapViewOfSection` and Friends
`ZwUnmapViewOfSection` is typically seen alongside `NtWriteVirtualMemory` and `NtResumeThread` in process hollowing chains. It also pairs with `CreateProcess` in suspended mode, which sets up the hollowing environment. The related `NtUnmapViewOfSection` API is functionally identical, with the difference lying in naming conventions between Nt* and Zw* calls.

## 📚 Resources
- [Microsoft Docs: ZwUnmapViewOfSection](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwunmapviewofsection)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!