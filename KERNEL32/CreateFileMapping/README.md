# 🛠️ CreateFileMapping: Mapping Memory, Masking Intent

## 🚀 Executive Summary
`CreateFileMapping` is a Win32 API that creates memory backed section objects, widely used for efficient file I/O and interprocess communication. But in malware and offensive tooling, it's a go to primitive for staging payloads, reflective loading, and stealthy injection. Often without touching disk. Its flexibility makes it a favorite for fileless execution, process hollowing, and shared memory attacks with low forensic footprint. Whether paired with `MapViewOfFile` or the native [NtMapViewOfSection](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/NTDLL/NtMapViewOfSection), this API is a quiet linchpin in both legitimate software and post exploitation tradecraft.

## 🔍 What is CreateFileMapping?
`CreateFileMapping` doesn’t open files; it maps them. Unlike `CreateFile`, which gives you a handle to interact with a file directly, `CreateFileMapping` builds a memory backed section object, letting processes treat file content (or raw memory) as part of their address space. When pointed at an actual file handle, it's a fast lane for nonlinear access and crossprocess sharing. When passed `INVALID_HANDLE_VALUE`, it spins up a chunk of memory backed by the system paging file.

## 🚩 Why It Matters
`CreateFileMapping` shows up in tooling, tradecraft, and telemetry. It’s a staple in legitimate software too; used to back memory with files, share data across processes, or allocate large memory regions without touching disk. But it also pops up in packers, payload staging, and process injection chains. When memory is mapped with `PAGE_EXECUTE_READWRITE` and no file backing, that’s worth a closer look. Paired with `MapViewOfFile`, it lets malware carve out executable memory on demand, no `VirtualAlloc` required. Understanding how, when, and why it’s used helps distinguish noise from threat.

## 🧬 How Attackers Abuse It
Malware leans on `CreateFileMapping` to carve out memory regions that double as payload staging grounds, shared or private, and either on disk or completely detached. When backed by `INVALID_HANDLE_VALUE`, it allocates a section object from the system paging file, giving attackers a clean, diskless space to stash shellcode or reflective DLLs. Pair it with `MapViewOfFile`, and you’ve got writable memory that can be flipped to executable and hijacked via remote threads, APCs, or classic ROP detours. It’s also a core primitive for interprocess injection: one process sets the section, another maps it, both access the same weaponized memory, often sidestepping AV hooks and catching static scanners off guard. This API keeps things low noise and memory resident.

## 🛡️ Detection Opportunities
Here are some sample YARA rules to detect suspicious use of `CreateFileMapping`:

See [CreateFileMapping.yar](./CreateFileMapping.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
`CreateFileMapping` followed by `MapViewOfFile` or [NtMapViewOfSection](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/NTDLL/NtMapViewOfSection) especially when no file is involved. Look for `INVALID_HANDLE_VALUE` (`0xFFFFFFFF`), which can signal fileless payload staging. Memory protections like `PAGE_EXECUTE_READWRITE` or `PAGE_READWRITE` on the section are worth flagging, particularly if followed by thread creation, remote injection, or shellcode like execution patterns. In multiprocess abuse, look for one process creating a mapping and another opening a handle and mapping the same section. Execution from memory regions tied to section objects rather than heap or stack also stands out. Coupled with network activity, suspicious child process creation, or indirect execution (APCs, callbacks, `NtCreateThreadEx`), this API becomes a high fidelity signal in post-exploitation chains.

### 🧩 Reverese Engineering Clues
In disassembly, calls to `CreateFileMappingW` or `NtCreateSection` often show up before a suspicious buffer gets written to. That memory is usually the staging ground. So pause here, deobfuscate, and inspect what’s being copied in. It’s often shellcode, a reflective DLL, or some other payload that’s about to be mapped and executed.

Look for a pattern: create section → map view → copy payload → jump. 

Cross-process variants will include `OpenProcess`, duplicated handles, and `MapViewOfFile` or [NtMapViewOfSection](../../NTDLL/NtMapViewOfSection/) pointing into a remote PID. If the section name is non-empty and oddly formatted (random GUIDs, junk strings), it might be used for covert IPC or persistence. Watch for memory mapped with `SEC_COMMIT` or `SEC_IMAGE`, especially if it resembles a PE header. This could indicate manual mapping or reflective loading.

## 🦠 Malware & Threat Actors Documented Abusing CreateFileMapping
Commodity loaders, modular RATs, and custom C2 implants all cozy up to `CreateFileMapping` when they want to stay off disk and under the radar. First stage droppers use it to unpack shellcode straight into memory. Reflective loaders hijack it to map PEs without touching CreateFile. And shared sections turn into backchannels for injecting modules across process boundaries. From remote access tools to bespoke red team kits, if the goal is stealth and flexibility, memory mapping commonly lurks somewhere in the kill chain.

### **Ransomware**
 - DarkSide
 - LockFile
 - REvil

### **Commodity Loaders & RATs**
 - Phorpiex Botnet
 - SocGholish

### **APT & Threat Actor Toolkits**
 - APT X
 - Iron Tiger
 - Agent Tesla

### **Red Team & Open Source Tools**
 - Cobalt Strike
 - Metasploit
 - Mimikatz

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `CreateFileMapping`.

## 🧵 `CreateFileMapping` and Friends
`CreateFileMapping` rarely works alone. It’s usually paired with `MapViewOfFile` to carve out and map memory regions, but attackers who want more control (or less visibility) reach for the native layer: [NtCreateSection](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/NTDLL/NtCreateSection) and `NtMapViewOfSection`. These syscalls offer the same core functionality. Creating and mapping memory backed sections. but with fewer guardrails and less userland telemetry. You’ll often see them in chains involving `DuplicateHandle`, [WriteProcessMemory](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/KERNEL32/WriteProcessMemory), or QueueUserAPC, depending on how the payload is meant to land. 

## 📚 Resources
- [Microsoft Docs: CreateFileMapping](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!