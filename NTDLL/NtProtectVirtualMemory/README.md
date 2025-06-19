# NtProtectVirtualMemory

## 🚀 Executive Summary
`NtProtectVirtualMemory` changes the protection on a region of memory in a process ... think flipping something from read-only to executable. It’s a core API in a lot of post-exploitation activity, especially when attackers want to run code they just wrote to memory. On its own, it’s noisy and shows up in plenty of legitimate software, but when used as part of an injection or evasion chain, it becomes a high-signal event. Whether it's making shellcode runnable, unhooking security tools, or quietly staging execution, this API is where a lot of abuse goes live.

## 🚩 Why It Matters
`NtProtectVirtualMemory` matters because it’s where things usually go live. You’ll see it right before shellcode execution, right after unhooking, or as part of evasion trickery. On its own, it's noisy, lots of legit software calls it, but when it's chained with memory allocation and writes, it's a strong tell. Catching it in context helps surface injection and bypass activity that might otherwise slip through.

## 🧬 How Attackers Abuse It
Changes memory protection on a region of pages in a process. Pages are fixed-size chunks of memory that make up a process’s virtual address space, managed by the OS. Attackers abuse this API to make normally non-executable memory regions runnable, letting them execute malicious code, evade hooks, and interfere with analysis.

- **Injection**: After allocating and writing shellcode to memory, attackers use `NtProtectVirtualMemory` to mark the region as executable.  
- **Unhooking**: Used to make hooked APIs writable, restore original bytes, and reapply execute permissions, bypassing EDR monitoring.  
- **Anti-debugging**: Alters memory tied to breakpoints and debugger stubs (e.g., `DbgBreakPoint`, `DbgUiRemoteBreakin`).  
- **Enclave abuse**: In rare cases, abused to modify permissions inside IUM/VBS enclaves (Isolated User Mode / Virtualization-Based Security) to hide execution from VTL0 (the normal Windows OS layer where most security tools run).

## NtProtectVirtualMemory Abuse Paths

Below are categorized examples of how attackers abuse `NtProtectVirtualMemory` as part of different techniques, including process injection, service injection, unhooking, anti-debugging, and enclave abuse.

### Process Injection: Inject and execute code in a remote process.

1. `OpenProcess` or `NtOpenProcess` – get a handle to target process  
2. `VirtualAllocEx` or `NtAllocateVirtualMemory` – allocate memory in the remote process  
3. `WriteProcessMemory` or `NtWriteVirtualMemory` – write payload into remote memory  
4. `NtProtectVirtualMemory` – change memory protection to `PAGE_EXECUTE_READWRITE`  
5. `CreateRemoteThread` or `NtCreateThreadEx` – execute the payload  

### Service Injection: Inject code into a service process, often during startup.
1. `OpenSCManager` + `OpenService` – find the target service  
2. `QueryServiceStatusEx` – ensure it’s running or starting  
3. `OpenProcess` or `NtOpenProcess` – get handle to the service process  
4. `NtAllocateVirtualMemory` – allocate memory  
5. `NtWriteVirtualMemory` – write payload  
6. `NtProtectVirtualMemory` – set memory to executable  
7. `NtCreateThreadEx` or APC-based execution – execute in service context  

### Unhooking: Disable or bypass user-mode hooks (like EDR hooking `ntdll.dll`).
1. `GetModuleHandle` / `LdrGetDllHandle` – locate `ntdll.dll` in memory  
2. `ReadProcessMemory` / custom syscall loader – get clean copy from disk or known-good source  
3. `NtProtectVirtualMemory` – mark hooked region as writable  
4. `memcpy` or custom loop – overwrite hooked functions with clean code  
5. `NtProtectVirtualMemory` – restore original permissions  

### Anti-Debugging: Prevent or break debugging and analysis tools


1. `NtQueryInformationProcess` or `CheckRemoteDebuggerPresent` – detect debugger  
2. `NtProtectVirtualMemory` – modify debugger or analysis tool memory to disable breakpoints or tam

## 🛡️ Detection Opportunities

### 🔹 YARA
Check out some sample YARA rules here: [NtProtectVirtualMemory.yar](./NtProtectVirtualMemory.yar).

> **Heads up:** These rules are loosely scoped and designed for hunting and research. They're **not** meant for production detection systems that require low false positives. Please test and adjust them in your environment.

### 🔸 Behavioral Indicators
You’re not going to catch abuse of `NtProtectVirtualMemory` just by looking for the call itself—plenty of legitimate software uses it. The giveaway is how it’s used. Malicious chains usually go: memory is allocated or written to (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`), then `NtProtectVirtualMemory` flips the permissions to executable, and a thread gets created (`NtCreateThreadEx`). That sequence—especially when it happens in processes that don’t normally inject code, like `explorer.exe` or `svchost.exe` ... is a strong signal. It gets even more suspicious if the target memory sits near known module boundaries or the `.text` section of something like `ntdll.dll`. Stack those events up in a short window and you’ve got behavioral detection with teeth.

## 🦠 Malware & Threat Actors Documented Abusing NtProtectVirtualMemory

### Ransomware
 - BlackCat/ALPHV
 - LockBit
 - Cl0p

### Commodity Loaders & RATs
 - DarkGate
 - Remcos RAT
 - Lumma Stealer

### APT & Threat Actor Toolkits
 - APT29 (Midnight Blizzard)
 - TA406
 - Volt Typhoon

### Red Team & Open Source Tools
 - Cobalt Strike
 - Brute Ratel C4
 - Sliver
 - Donut
 - ScareCrow

> **Note:** This list isn't exhaustive. Many modern malware families and offensive security tools use `NtProtectVirtualMemory` for code injection and memory manipulation.

## 🧵 `NtProtectVirtualMemory` and Friends
`NtProtectVirtualMemory` gets a lot of attention, but it’s not the only way attackers flip memory protections. There’s a whole set of APIs that do the same thing or close enough—just from different angles. `VirtualProtect` and `VirtualProtectEx` are the obvious ones and basically wrap the same syscall, so if you're watching one, you should be watching all three. `ZwProtectVirtualMemory` is functionally the same as `NtProtectVirtualMemory`, but shows up in tooling that’s trying to slip past lazy detections. In .NET payloads, you'll sometimes see `ChangeMemoryProtection` used to adjust page protection similarly.

## 📚 Resources
[NTAPI Undocumented Functions](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtProtectVirtualMemory.html)

[Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas) (more like this)

> **Know of more?**  
> Open a PR or issue to help keep this list up to date!