# 🛠️ WriteProcessMemory: 

## 🚀 Executive Summary

## 🔍 What is WriteProcessMemory?
`WriteProcessMemory` is a core part of the Windows debugging and introspection toolchain. It allows a process with sufficient privileges to write directly into the memory of another process.  It is commonly used by debuggers to patch instructions, insert breakpoints, or modify variables at runtime. It also shows up in software updaters, automation tools, and systems management frameworks that need to inject configuration or adjust process behavior without restarting. When used legitimately, it's always in a high-privilege, high-trust context.  The caller will have full access and the memory writes are tightly scoped and intentional.

## 🚩 Why It Matters
`WriteProcessMemory` sits at the heart of countless post-exploitation techniques. It’s a low-noise, high-impact primitive that attackers reach for when they want to manipulate memory across process boundaries. For defenders, it’s a behavioral anchor (something that rarely shows up without intent). Whether you're building detections, reversing implants, or designing evasive payloads, understanding this API is table stakes.

## 🧬 How Attackers Abuse It
 - **Classic DLL Injection**: Writes the DLL path into remote memory before calling `CreateRemoteThread` or `NtCreateThreadEx` to load it via `LoadLibrary`.
 - **Reflective DLL Injection**: Drops a custom loader and in-memory PE image into a remote process; bypassing LoadLibrary entirely.
 - **Shellcode Injection**: Writes raw shellcode into remote memory and executes it with `CreateRemoteThread`, `NtQueueApcThread`, or `RtlCreateUserThread`.
 - **Process Hollowing**: Hollowed target is unwrapped with `WriteProcessMemory` to overwrite its image with a malicious payload post-CreateSuspended.
 - **Thread Hijacking**: Writes shellcode into an existing thread’s memory space, then redirects execution with `SetThreadContext` or `QueueUserAPC`.
 - **Code Patching/Hooking**: Overwrites functions or syscalls in a remote process (like import or export table patching, inline hooks) to alter behavior or evade detection.
 - **Implant Configuration Injection**: Drops configuration blobs or encrypted payloads directly into an implant’s memory for runtime decryption and execution.
 - **Inter-Process Data Staging**: Used for staging larger payloads or artifacts across multiple processes, often combined with named pipe or shared memory comms.
 - **Memory Tunneling/Stomping**: Writes into the memory space of trusted processes (commonly explorer.exe) to hide malicious code execution behind legitimate processes.

## 🛡️ Detection Opportunities

Here are some sample YARA rules to detect suspicious use of `WriteProcessMemory`:

See [WriteProcessMemory.yar](./WriteProcessMemory.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
`WriteProcessMemory` doesn’t hide well. It leaves behind footprints. The trick is knowing what patterns to watch for. Here’s your quick-hitter reference for spotting abuse across injection, hollowing, staging, and more:

#### Process Injection (Classic, Reflective, Shellcode)
 - `WriteProcessMemory` paired with `VirtualAllocEx` + `CreateRemoteThread` or `NtCreateThreadEx`
 - Source process has `PROCESS_ALL_ACCESS` or `PROCESS_VM_WRITE` to another running process
 - Target process is a high-trust binary (explorer.exe, svchost.exe, lsass.exe)
 - Remote thread creation into another PID
 - Injection into recently spawned, suspended processes

#### Process Hollowing
 - Process created in `CREATE_SUSPENDED` state, then hollowed via `WriteProcessMemory`
 - Large memory writes to the .text or image base of the suspended process
 - Immediate call to `SetThreadContext` or `ResumeThread` after memory overwrite
 - Mismatch between image on disk and memory-resident version (entropy, sections, PE headers)

#### Thread Hijacking
 - Existing thread opened with `THREAD_ALL_ACCESS` or `THREAD_SET_CONTEXT`
 - `WriteProcessMemory` used on the same process, not a child
 - Followed by `SetThreadContext`, `QueueUserAPC`, or `NtContinue`

#### Import/Export Address Table Patching
 - Memory writes to `.idata` or `.rdata` sections - Pointers inside immport or export address tables redirected to non-module regions (RWX heap, shellcode)
 - Loaded module modifies the import table of another loaded module

#### Config Injection & Staging
 - Repeated small memory writes with no thread creation
 - `WriteProcessMemory` used without code execution—likely data injection
 - Encrypted blobs or config patterns present in remote memory
 - Paired with named pipes or shared memory activity for post-write communication

#### Stomping / Evasion via Trusted Process
 - `WriteProcessMemory` used on long-lived system processes (explorer.exe)
 - No child/parent relationship between the injector and the target
 - Low or no disk I/O from target process, yet suspicious memory activity

#### More Generally
 - Track `WriteProcessMemory` + remote thread creation chains across unrelated processes
 - Alert on processes writing to `.text` or `.rdata` in another binary
 - Combine API telemetry with image load events, thread start origins, and memory protections
 - Flag cross-process memory writes to or from unexpected parent-child pairings
 - Compare PE header in memory vs on disk with PE-sieve or Volatility

## 🦠 Malware & Threat Actors Documented Abusing WriteProcessMemory
`WriteProcessMemory` is so deeply woven into modern offensive tooling that listing examples almost feels redundant, but here we are. It shows up in Cobalt Strike, Metasploit, Empire, Sliver, and countless DIY loaders across GitHub. It’s a favorite in custom tradecraft used by APTs and red teams alike, whether they’re injecting shellcode, hollowing processes, or patching function tables on the fly. If you're analyzing malware and don’t see `WriteProcessMemory`, odds are you're either too early in execution… or not looking hard enough.

### **Ransomware**
 - Magnibar
 - REvil
 - Ryuk

### **Commodity Loaders & RATs**
 - QuasarRAT
 - Emotet
 - Remcos

### **APT & Threat Actor Toolkits**
 - APT28 (Fancy Bear/Strontium)
 - APT41 (Double Dragon)
 - APT33 (Elfin/Magnallium)

### **Red Team & Open Source Tools**
- Cobalt Strike
- Empire
- Metasploit
- Sliver

> **Note:** This list is far from exhaustive. more modern malware families and offensive security tools use `WriteProcessMemory` for stealth and evasion.

## 🧵 `WriteProcessMemory` and Friends
While `WriteProcessMemory` is the go-to for cross-process memory injection, it’s not the only game in town. Attackers looking to fly lower or avoid API-based detections often pivot to `NtWriteVirtualMemory`, the native syscall version tucked inside `ntdll.dll`. It offers the same functionality but bypasses higher-level logging and some security hooks. For attackers already in kernel mode, `MmCopyVirtualMemory` delivers similar memory manipulation between processes. In rare cases, malware might even use manual mapping to avoid `WriteProcessMemory` entirely; resolving target addresses and writing memory byte-by-byte using direct pointer access and custom syscalls. While there’s no perfect one-to-one replacement in user mode, there are enough adjacent primitives to keep defenders guessing and attackers flexible.

## 📚 Resources
- [Microsoft Docs: WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!