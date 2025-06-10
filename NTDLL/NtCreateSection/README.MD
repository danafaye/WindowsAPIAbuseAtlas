# 🧪 NtCreateSection: The Swiss Army Knife of Memory Abuse

## 🚀 Executive Summary

`NtCreateSection` is one of those sleeper APIs that doesn’t get enough attention. It gives attackers a way to carve out memory, mapped from a file or just fresh, and drop it into a process. From there, it's open season: hollowing, reflective DLLs, shared memory tricks, you name it. Since it flies lower than the usual VirtualAlloc stuff, a lot of tooling just plain misses it.

## 🔍 What is NtCreateSection?

`NtCreateSection` is one of those low-level Windows APIs that quietly does a lot of heavy lifting for attackers. It lets you carve out a chunk of memory, either fresh or tied to a file, and map it into a process’s address space. That opens the door for all kinds of fun: process hollowing, reflective DLL injection, memory sharing across processes, you name it. Because it's deeper in the stack than typical alloc APIs, a lot of security tools just don’t see it coming.

## 🚩 Why It Matters

 - **Low-level memory games**: Lets attackers set up and share memory in ways that slip past a lot of detections.
 - **Injection-friendly**: Shows up in process hollowing, reflective DLLs, and other tricks you’d rather not see mid-incident.
 - **Everyone’s using it**: Commodity malware, red teams, APTs—it’s in the toolbox for a reason.

## 🧬 How Attackers Abuse It

- Create a section object with `NtCreateSection`.
- Map the section into the address space of the target process (using `NtMapViewOfSection`).
- Write malicious code or payloads into the mapped section.
- Execute the payload in the context of the target process, often bypassing user-mode hooks and security controls.

## 🧵 Sample Behavior

- Calls to `NtCreateSection` followed by `NtMapViewOfSection` and memory writing APIs.
- Section objects with suspicious permissions (e.g., `PAGE_EXECUTE_READWRITE`).
- Memory regions mapped into multiple processes.
- Seen in process hollowing, code injection, and reflective loading scenarios.

## 🛡️ Detection Opportunities

### 🔹 YARA

Here are some sample YARA rules to detect malicious use of `NtCreateSection`: 

See [NtCreateSection.yar](./NtCreateSection.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🔹 Behavioral Indicators

- Unusual use of section objects with executable permissions (e.g., `PAGE_EXECUTE_READWRITE`), especially when not typical for the application.
- Mapping the same section object into multiple processes, which can indicate code or payload sharing for injection or hollowing.
- Sequence of section creation (`NtCreateSection`), mapping (`NtMapViewOfSection`), and remote thread creation (`CreateRemoteThread`, `NtCreateThreadEx`), often seen in process hollowing or reflective DLL injection.
- Rapid succession of memory allocation, mapping, and thread manipulation APIs, particularly in processes that do not normally perform such operations.
- Section objects with names or attributes that are unusual, random, or inconsistent with legitimate application behavior.
- Memory regions mapped as executable in processes that typically do not require dynamic code execution.
- Parent-child process relationships where the parent process creates a section and maps it into the child, followed by suspicious thread activity.
- Use of `NtUnmapViewOfSection` to remove legitimate code before mapping a new section, a common step in process hollowing.
- Lack of corresponding file-backed sections (i.e., sections not tied to legitimate files on disk), suggesting in-memory payload delivery.
- Correlation with other injection or evasion techniques, such as disabling security tools, modifying access controls, or tampering with process attributes.

## 🦠 Malware & Threat Actors Documented Abusing NtCreateSection

Below is a curated list of malware families, threat actors, and offensive tools known to abuse or patch `NtCreateSection`.  

For the latest technical write-ups, search for the malware, tool or actor name together with "NtCreateSection" on reputable security blogs, threat intelligence portals, or simply google. (Direct links are not included to reduce maintenance.)

### **Ransomware**
- Agenda
- Magniber
- LockPoS
- NotPetya

### **Commodity Loaders & RATs**
 - BabbleLoader
 - DarkVision RAT
 - IDAT Loader
 - GULoader
 - NanoCore RAT
 - Remcos RAT
 - SmokeLoader
 - Winnti Spyder Loader

### **APT & Threat Actor Toolkits**
 - APT29 (aka Nobelium, UNC2452, Cozy Bear)
 - APT41 (aka Double Dragon)
 - CosmicStrand (Unknown Chinese-speaking threat actor)
 - Earth Berberoka (aka GamblingPuppet)
 - Lazarus Group 

### **Red Team & Open Source Tools**
 - Brute Ratel C4
 - CobaltStrike
 - Metasploit
 - PoshC2
 - Sliver

> **Note:** This list isn’t exhaustive. Many modern malware families and offensive security tools use `NtCreateSection` for stealth and evasion. As awareness grows, expect even more to adopt it.

## 🧵 `NtCreateSection` and Friends

**`NtCreateSection`** is part of a family of native APIs that enable low-level memory and object manipulation, including `NtMapViewOfSection`, `NtUnmapViewOfSection`, and `NtProtectVirtualMemory`. Attackers often chain these APIs together for advanced injection and evasion techniques. Monitoring for the combined use of these functions can help defenders spot sophisticated attacks before they escalate.

## 📚 Resources

- [Microsoft Docs: NtCreateSection](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-ntcreatesection)
- [Process Injection Techniques](https://attack.mitre.org/techniques/T1055/)

> **Know of more?**  
> Open a PR or issue to help keep this list up to date!