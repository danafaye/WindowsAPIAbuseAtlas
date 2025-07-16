# 🛠️ NtQueryVirtualMemory: 

## 🚀 Executive Summary
`NtQueryVirtualMemory` is a low noise API that offers deep visibility into the memory layout of any process it touches. It’s widely abused in modern tooling to map memory, locate injected payloads, and identify modules. All without reading or modifying a single byte. Frequently paired with `OpenProcess` and other memory inspection calls, it plays a critical role in preinjection recon, sandbox evasion, and stealthy enumeration. Whether used by loaders, implants, or red team frameworks, its presence often signals something is sizing up memory before making its move.

## 🔍 What is NtQueryVirtualMemory?
`NtQueryVirtualMemory` is a low-level API that gives developers a detailed view into the memory layout of a process. It’s called *virtual memory* because the memory addresses seen by a process are part of a virtual address space, which are mapped and managed by the OS, not tied directly to physical RAM. Legitimate tools use this API to inspect memory regions, query protection flags, identify mapped files, or troubleshoot heap usage. Debuggers and profilers lean on it to understand memory fragmentation or to walk `VirtualAlloc`ed regions with precision. Backup software might also query mapped sections to skip volatile or unnecessary memory. Its flexibility makes it a powerful tool for diagnostics, optimization, and memory analysis. Especially when higher level APIs fall short or lack the granularity needed.

## 🚩 Why It Matters
`NtQueryVirtualMemory` is a favorite among malware authors for its ability to silently explore a process’s memory without raising many flags. It can reveal loaded modules, mapped DLLs, injected code regions, or even uncover hooks and debuggers. This is all without the overhead of higher level APIs. Threats use it to fingerprint their environment, locate sensitive structures, or carve out injection targets. Because it doesn’t require code execution in the remote process, it’s ideal for *passive* reconnaissance and evasion. Familiarity with this API is key to recognizing behaviors that blend in with legitimate tools but carry the subtle fingerprints of stealth.

## 🧬 How Attackers Abuse It: Passive Recon
`NtQueryVirtualMemory` is a surgical tool for memory reconnaissance. In adversarial hands, it enables silent, code-free inspection of a remote process. Threat actors abuse it to locate injectable memory, unbacked executable regions, or juicy modules like `amsi.dll`, `clr.dll`, or security tool hooks, all without ever executing code in the target process. It slips under the radar by avoiding noisier functions like `ReadProcessMemory` or [CreateRemoteThread](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/KERNEL32/CreateRemoteThread).

A common abuse chain starts with `OpenProcess` (or its lower level counterpart `NtOpenProcess`) to grab a handle with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`. From there, `NtQueryVirtualMemory` iterates through memory regions probing for `MEM_IMAGE`, `MEM_PRIVATE`, or `MEM_MAPPED` types, and zeroing in on regions with `PAGE_EXECUTE_READWRITE` or anomalous memory protection flags.

When the attacker needs module paths, the call uses the `MemorySectionName` class to reveal full DLL names even for manually mapped or hidden modules. If they’re hunting for injection targets, they’ll combine it with `VirtualQueryEx`, `ReadProcessMemory`, or `NtReadVirtualMemory` to verify contents before injecting via [NtWriteVirtualMemory](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/NTDLL/NtWriteVirtualMemory) or [VirtualAllocEx](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/KERNEL32/VirtualAllocEx).

In more advanced tooling, `NtQueryVirtualMemory` supports selective targeting: malware will locate only the region where their shellcode was mapped (like by parent or sibling process), or confirm that their payload hasn’t been tampered with. Red teams and threats alike use this API as the scout before the breach. It's like the flashlight that shines just enough light to strike without tripping the alarms.

## 🛡️ Detection Opportunities
Here are some sample YARA rules to detect suspicious use of `NtQueryVirtualMemory`:

See [NtQueryVirtualMemory.yar](./NtQueryVirtualMemory.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - **Unusual Pairings**: Look for `NtQueryVirtualMemory` used in close sequence with `OpenProcess`, `NtOpenProcess`, or `CreateToolhelp32Snapshot` targeting security tools or sibling processes.
 - **Memory Snooping Without Execution**: Processes that enumerate memory regions (`MemoryBasicInformation`) or section names (`MemorySectionName`) without any corresponding memory writes or threads may be staging for evasion or module discovery.
 - **Querying Executable and RWX Memory**: Calls that enumerate `PAGE_EXECUTE_READWRITE`, `PAGE_EXECUTE_READ`, or `MEM_IMAGE` regions. Especially in security sensitive processes can indicate stealthy recon or shellcode hunting.
 - **No Legit Context**: When `NtQueryVirtualMemory` is called outside of debuggers, profilers, or backup contexts; especially from script interpreters (PowerShell, wscript) or unknown binaries.
 - **Used Before Injection APIs**: Watch for it preceding [VirtualAllocEx](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/KERNEL32/VirtualAllocEx), [NtWriteVirtualMemory](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/NTDLL/NtWriteVirtualMemory), or [CreateRemoteThread](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/KERNEL32/CreateRemoteThread). It’s often step zero in a reflective injection or module stomping routine.
 - **Suspicious Module Name Queries**: Requests for section names resolving to `amsi.dll`, `clr.dll`, `dbghelp.dll`, or EDR DLLs could signal reconnaissance or hook discovery.
 - **Abused in LOLBins**: Abuse via signed, but unusual binaries (rundll32.exe, msbuild.exe) that shouldn't be introspecting memory is a telltale tactic.
 - **Frequency Spikes**: A spike in `NtQueryVirtualMemory` calls per process lifetime. Especially when paired with minimal standard API usage can flag tooling like in memory loaders or remote access payloads.

## 🦠 Malware & Threat Actors Documented Abusing NtQueryVirtualMemory
`NtQueryVirtualMemory` is commonly abused in malware that prioritizes memory reconnaissance and stealth over brute force. It shows up in reflective loaders, shellcode injectors, and custom tooling built for in memory execution.

### **Ransomware**
 - Locky
 - Likely found more in the loaders. If you  know of more let me know, and I'll add them.

### **Commodity Loaders & RATs**
 - DorkBot
 - GuLoader
 - Necurs Botnet
 - Raspberry Robin

### **APT & Threat Actor Toolkits**
 - APT29
 - APT41
 - Lazarus

### **Red Team & Open Source Tools**
 - NimDump
 - Shellter
 - Sliver

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `NtQueryVirtualMemory` for stealth and evasion.

## 🧵 `NtQueryVirtualMemory` and Friends
`NtQueryVirtualMemory` isn’t the only way to peek into another process. It’s just the one with the finest detail. Its high-level sibling, [VirtualAllocEx](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/KERNEL32/VirtualAllocEx), is often the first stop. It sketches out memory regions, protection flags, and allocation types. Fast and easy to use, but shallow. When deeper inspection is needed, attackers reach for `ReadProcessMemory` or `NtReadVirtualMemory` to extract raw bytes from scoped regions. Usually after mapping memory layout with `NtQueryVirtualMemory` or `VirtualQueryEx`.

Functionally identical to `NtQueryVirtualMemory`, the `ZwQueryVirtualMemory` variant shows up too, technically different entry point, same behavior. And when malware wants to double check what the OS says is loaded, it leans on `NtQueryVirtualMemory` to validate what `EnumProcessModules` or `CreateToolhelp32Snapshot` report. Those higher level APIs can lie or miss manually mapped modules.

Supporting tools round out the kit. `QueryWorkingSetEx` and `NtQueryInformationProcess` can expose residency, layout hints, or environment clues. All useful in sandbox detection or injection prep. And when the goal is to tie memory back to disk, `GetMappedFileName` offers a different path to the same insight as `NtQueryVirtualMemory`’s `MemorySectionName`.

None of these APIs match `NtQueryVirtualMemory` in isolation. But together, they give malware a modular, layered toolkit for memory mapping, module discovery, and stealthy reconnaissance without ever touching a single instruction in the target process.

## 📚 Resources
- [Microsoft Docs: NtQueryVirtualMemory](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvirtualmemory)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!