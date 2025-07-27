# 🛠️ CreateFileMapping: Mapping Memory, Masking Intent

## 🚀 Executive Summary
`CreateFileMapping` is a Win32 API that creates a memory backed section object, commonly used for efficient file I/O and inter process communication. In offensive tooling and malware, it’s repurposed to allocate memory for payload staging, reflective loading, and stealthy injection often avoiding disk entirely. Threat actors favor it for its flexibility: it enables fileless execution, process hollowing, and shared-memory attacks with minimal footprint. Whether paired with `MapViewOfFile` or its native counterpart [NtMapViewOfSection](../../NTDLL/NtMapViewOfSection/), this API is a quiet workhorse in both legitimate software and post-exploitation chains, making its presence in telemetry worth a closer look.

## 🔍 What is CreateFileMapping?
`CreateFileMapping` is a Windows API used to establish a memory mapped file object, allowing a process to map a file’s contents or a block of system memory into its address space. This API is commonly used for efficient file I/O, particularly when large files need to be accessed in a nonlinear fashion or shared between processes. When backed by `INVALID_HANDLE_VALUE`, it creates a region of memory backed by the system paging file, effectively enabling shared memory communication between related or unrelated processes. It’s a foundational mechanism in Windows for scenarios involving caching, IPC (interprocess communication), or performance critical data handling, offering a way to avoid repetitive disk reads or complex serialization.

## 🚩 Why It Matters
`CreateFileMapping` shows up in tooling, tradecraft, and telemetry. It’s a staple in legitimate software—used to back memory with files, share data across processes, or allocate large memory regions without touching disk. But it also pops up in packers, payload staging, and process injection chains. When memory is mapped with `PAGE_EXECUTE_READWRITE` and no file backing, that’s worth a closer look. Paired with `MapViewOfFile`, it lets malware carve out executable memory on demand, no `VirtualAlloc` required. Understanding how, when, and why it’s used helps distinguish noise from threat.

## 🧬 How Attackers Abuse It
Malware leans on `CreateFileMapping` to quietly set up shared or private memory regions that double as staging areas for payloads. When used with `INVALID_HANDLE_VALUE`, it creates a memory backed section detached from the filesystem ideal for loading shellcode or reflective DLLs without touching disk. Attackers often combine it with `MapViewOfFile` to write code into memory, mark it executable, and run it via a thread hijack, APC queue, or ROP chain. It also shows up in interprocess injection techniques: one process creates the mapping, another maps it, and both share access to the same malicious payload sidestepping some common detection mechanisms. It’s a favorite for keeping operations fileless, memory resident, and evasive.

## 🛡️ Detection Opportunities

Here are some sample YARA rules to detect suspicious use of `CreateFileMapping`:

See [CreateFileMapping.yar](./CreateFileMapping.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
`CreateFileMapping` followed by `MapViewOfFile` or `NtMapViewOfSection` especially when no file is involved (look for `INVALID_HANDLE_VALUE`) can signal fileless payload staging. Memory protections like `PAGE_EXECUTE_READWRITE` or `PAGE_READWRITE` on the section are worth flagging, particularly if followed by thread creation, remote injection, or shellcode like execution patterns. In multiprocess abuse, look for one process creating a mapping and another opening a handle and mapping the same section. Execution from memory regions tied to section objects rather than heap or stack also stands out. Coupled with network activity, suspicious child process creation, or indirect execution (APCs, callbacks, `NtCreateThreadEx`), this API becomes a high fidelity signal in post-exploitation chains.

### 🧩 Reverese Engineering Clues
In disassembly, calls to `CreateFileMappingW` or `NtCreateSection` often come before a buffer is written with suspicious content deobfuscate and inspect what’s being copied in. 

Look for a pattern: create section → map view → copy payload → jump. 

Cross-process variants will include OpenProcess, duplicated handles, and `MapViewOfFile` or [NtMapViewOfSection](../../NTDLL/NtMapViewOfSection/) pointing into a remote PID. If the section name is non-empty and oddly formatted (random GUIDs, junk strings), it might be used for covert IPC or persistence. Watch for memory mapped with `SEC_COMMIT` or `SEC_IMAGE`, especially if it resembles a PE header—this could indicate manual mapping or reflective loading.

## 🦠 Malware & Threat Actors Documented Abusing CreateFileMapping
Commodity loaders, modular RATs, and custom C2 implants all dip into `CreateFileMapping` to keep their payloads off disk and under the radar. It’s used in first stage droppers that unpack shellcode into memory, in rats that inject modules into remote processes via shared sections, and in reflective loaders that repurpose it to map PE files directly into memory. Whether it’s a cracked NanoCore variant or a bespoke red team tool, if stealth and flexibility are priorities, memory mapping is usually in the mix.

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
`MapViewOfSection` is the native way to do what `MapViewOfFile` does, but it’s more flexible, less visible to userland monitoring, and more popular in low level malware. If `CreateFileMapping` and `MapViewOfFile` are the safe, documented surface… `NtCreateSection` and [NtMapViewOfSection](../../NTDLL/NtMapViewOfSection/) are the sharp tools attackers use when they’re building something custom.

## 📚 Resources
- [Microsoft Docs: CreateFileMapping](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!