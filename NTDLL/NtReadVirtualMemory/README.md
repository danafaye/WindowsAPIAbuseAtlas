# 🛠️ NtReadVirtualMemory

## 🚀 Executive Summary
`NtReadVirtualMemory` is a low level Windows native API that reads memory from a target process. It’s the direct system call counterpart to the more familiar `ReadProcessMemory`. Defenders should care because this primitive sits at the heart of a lot of nasty things: credential theft (reading LSASS), token theft, reconnaissance of injected code, and staging for process injection or evasion.
This post breaks down what it is, how it’s abused, what to look for, and practical detections you can start experimenting with today.

## 🔍 What is NtReadVirtualMemory?
At its core, `NtReadVirtualMemory` is exported from `ntdll.dll` and serves as the system call gateway for reading another process’s memory. The calling process supplies a handle to the target, the base address to read from, the size of the memory region, and a buffer to receive the data. When executed, the kernel copies the requested memory into the attacker’s buffer.

So why use it instead of `ReadProcessMemory`? Many offensive tools prefer the NT API because higher level Win32 functions are more heavily monitored by EDR solutions. By invoking `NtReadVirtualMemory` directly or even bypassing `ntdll.dll` imports altogether via direct syscalls attackers can achieve the same functionality with a lower detection footprint.

## 🚩 Why It Matters
The ability to read memory across process boundaries is a powerful capability. Credential theft is the most obvious case, with attackers using this function to scrape secrets directly from LSASS without generating a full minidump. But that’s just the beginning. `NtReadVirtualMemory` can be used to read token data structures for impersonation, to harvest in memory configurations from competing malware or defensive software, and to scan loaded modules for useful function addresses.

Equally important is its role in evasion. While security products know to monitor `ReadProcessMemory` or `MiniDumpWriteDump`, they are less likely to catch a well placed syscall to `NtReadVirtualMemory`. This makes it a staple of modern offensive tradecraft.

## 🧬 How Attackers Abuse It
Attackers put `NtReadVirtualMemory` to work in several ways. Credential access is one of the most common, with malware opening a handle to LSASS and pulling memory in chunks that can be parsed offline to recover usernames and passwords. Others use it to target specific data structures like access tokens, which can then be replayed to pivot identities. Reconnaissance is another use case: by reading process structures, export tables, or configuration blocks, attackers gain insight into what’s running in memory and how it might be subverted.

Process injection also relies on this API. After code is placed into a remote process, attackers can read it back to verify placement or extract shellcode. Meanwhile, more advanced adversaries will skip imports altogether, resolving the syscall number at runtime and invoking `NtReadVirtualMemory` via hand rolled assembly stubs. This approach sidesteps user mode hooks and further complicates detection.

## 🛡️ Detection Opportunities
Detection is difficult because legitimate tools also use this API. The key is to focus on context and correlation rather than the function call itself. Here are a few promising angles:

 - **Handle and access analysis**: Watch for processes that open handles to sensitive targets like `lsass.exe` with `PROCESS_VM_READ` rights, especially when followed quickly by memory reads.
 - **Unusual call origins**: Investigate when `NtReadVirtualMemory` is invoked from unsigned or unexpected modules, or when a process lacking diagnostic purpose suddenly performs memory reads.
- **Direct-syscall indicators**: Look for syscall stubs that bypass imports, particularly when no Win32 memory reading functions are present in the binary.
 - **Target-centric monitoring**: Track nonadmin or nondebugger processes accessing LSASS, browser processes, or security tools. Reads that align with PE header boundaries or known credential structures are especially suspect.
 - **Telemetry fusion**: Use ETW, Sysmon (Event ID 10), or EDR sensors to correlate handle opens, process access, and image loads around suspicious reads.

Here are some sample YARA rules to detect suspicious use of `NtReadVirtualMemory`:

See [NtReadVirtualMemory.yar](./NtReadVirtualMemory.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
Suspicious patterns include binaries launched from temporary or user profile locations that almost immediately open a handle to LSASS and perform memory reads. Short lived processes that do nothing but open a process, read memory, and exit should be investigated. Other signals include binaries that import `NtReadVirtualMemory` but omit higher level APIs like `ReadProcessMemory`, or those that embed direct syscall stubs while dynamically resolving ntdll exports. Reading memory in ways that line up with PE header boundaries or module lists can also stand out as attacker behavior.

## 🦠 Malware & Threat Actors Documented Abusing NtReadVirtualMemory

### **Ransomware**
- BabLock
- BlackByte
- Matabuchus 3.0

### **Commodity Loaders & RATs**
- HijackLoader
- Gootkit
- Rhadamanthys
f
### **APT & Threat Actor Toolkits**
- Lazarus
- Winnti 

### **Red Team & Open Source Tools**
- MemorySnitcher
- Mimikatz

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `NtReadVirtualMemory`.

## 🧵 `NtReadVirtualMemory` and Friends
This API rarely appears alone. Attackers usually begin by acquiring a process handle with functions like `NtOpenProcess` or `OpenProcess`. They may query system information or process details with `NtQuerySystemInformation` or `NtQueryInformationProcess` before beginning the read. Variants exist as well: `ReadProcessMemory` is the higher level counterpart, and `NtWow64ReadVirtualMemory64` supports cross architecture reads.

In more advanced scenarios, `NtReadVirtualMemory` is paired with write and allocation APIs such as `NtWriteVirtualMemory` and `NtAllocateVirtualMemory` to facilitate injection. Attackers often combine it with `NtProtectVirtualMemory` to change permissions or `NtCreateThreadEx` to execute payloads. In evasion heavy campaigns, it is seen alongside functions like `LdrLoadDll` or manual mapping routines used to resolve exports and unhooked function addresses.

## 📚 Resources
- [NTAPI Undocumented Functions: NtReadVirtualMemory](http://undocumented.ntinternals.net/index.html?page=UserMode/Undocumented+Functions/Memory+Management/Virtual+Memory/NtReadVirtualMemory.html)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!