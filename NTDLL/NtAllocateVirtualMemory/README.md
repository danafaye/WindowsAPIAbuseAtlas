# 🪄 NtAllocateVirtualMemory

## 🚀 Executive Summary
`NtAllocateVirtualMemory` is the lowlevel `ntdll` primitive that hands you raw slices of a process’s address space. It’s the plumbing behind `VirtualAlloc`, `VirtualAllocEx` and friends. These are places malicious actors ask the OS politely (or not so politely) for memory to stuff code into, map data, or carve out a trampoline. If you see an unexpected allocation followed by writes, a protection change to make memory executable, or a thread soon afterwards, your detector senses should start humming.

## 🔍 What is NtAllocateVirtualMemory?
`NtAllocateVirtualMemory` is the native syscall that reserves and/or commits virtual memory in a process. Callers provide a process handle, a pointer to a base address (can be NULL to let the OS pick), a requested region size, an allocation type (reserve, commit, or both), and a protection constant (read/write/execute combinations). The function lives in `ntdll` and is usually invoked either via the documented higher-level APIs (`VirtualAlloc` / `VirtualAllocEx`) or directly through its syscall stub. On success you get back an address where the OS set aside memory; on failure you get a STATUS code.

## 🚩 Why It Matters
Memory allocation is the first step in a lot of post exploitation choreography. Whether an adversary is trying to run shellcode, stage a reflective loader, unhook a DLL, map a PE image manually, or just stash configuration and keys in a place with no file backing. It all often starts with asking the kernel for virtual memory. That single syscall sits at the crossroad between benign program behavior (legit apps allocate memory all the time) and very suspicious activity (remote allocations into other processes, RWX pages, followed by remote thread creation). Because of that, `NtAllocateVirtualMemory` is both a blunt instrument for attackers and a useful signal for defenders, if you watch it with context, it’s valuable.

> Note: Virtual memory is an OS managed "illusion" that gives each process its own private address space so programs use "virtual" addresses instead of actual physical RAM addresses directly. The OS handles mapping the virtual addresses onto real physical memory (and the pagefile on disk when needed), letting many programs share limited RAM safely and efficiently.

## 🧬 How Attackers Abuse It
Attackers use `NtAllocateVirtualMemory` in a handful of archetypal ways:

 - **Memory allocation + write + execute**: attacker allocates memory, writes shellcode or a loader into it, makes it executable, then runs it (the classic “allocate → write → exec” chain).

 - **Process injection / remote staging**: attacker allocates memory inside another process, drops code there, and forces it to run.

 - **Reflective PE loading and in-memory unpacking**: instead of writing a file, malware builds or unpacks a PE straight in memory (sections, imports, relocations) and then starts it.

 - **Memory-only persistence and tooling**: some malware and red team tools keep payloads and configs purely in RAM to avoid touching disk.

 - **Code caves and trampolines**: attackers (and some legitimate tools) allocate memory to hold small injected stubs, JIT code, or trampoline hooks.

 - **Sandbox evasion and staged unpacking**: malware often delays staging/decoding into memory until it’s sure it’s not being monitored, then allocates and runs the unpacked code.

## 🛡️ Detection Opportunities
You cannot treat every allocation as hostile. Legitimate software allocates memory constantly. But the context around allocations gives you traction.

 - Look for `RWX pages`. Memory regions created with execute permission combined with write permission (`PAGE_EXECUTE_READWRITE`) are uncommon in well behaved applications. If you see allocation flags or subsequent `NtProtectVirtualMemory` calls making pages executable, raise suspicion.

  - Watch allocations into other processes. When a process opens another process handle and calls `NtAllocateVirtualMemory` with that handle (or you observe `VirtualAllocEx` style behavior), couple that with subsequent writes and thread creation and you probably have an injection chain.

 - Sequence analysis buys you signal: allocate → write → change-protect-to-exec → create-thread / queue-apc is the canonical malicious flow. It's the whole chain that matters more than the single syscall.

 - Pay attention to size and alignment. Very large anonymous allocations in short lived processes, or allocations at unusually aligned base addresses, can be suspicious depending on context.

 - Parent/child and provenance checks. If a low privileged process triggers `RWX` allocations in a high value process or a process that historically never makes allocations like that (browser plugin host, print spooler, or similar), escalate.

 - Syscall only actors. Some malware calls `NtAllocateVirtualMemory` directly via the syscall number rather than via documented APIs to evade user mode hooks. Monitoring raw syscall activity or at least detecting unusual stub patterns is useful for hunting.

 - Memory without file backing. Allocations that contain PE headers or mapped image like patterns but are never backed by a file are a red flag for in memory loaders.

 - Telemetry correlation is king. Alone, one allocation doesn’t prove anything. Correlate with process ancestry, network activity (beaconing after injection), suspicious handle opens (`OpenProcess` with `PROCESS_ALL_ACCESS`), and known suspicious sequences.

Here are some sample YARA rules to detect suspicious use of `NtAllocateVirtualMemory`:

See [NtAllocateVirtualMemory.yar](./NtAllocateVirtualMemory.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - Allocation made into a remote process handle, followed quickly by memory writes and a thread creation or APC.

 - Allocation requesting execute permissions or memory that later receives a protection change to executable.

 - Anonymous memory region containing PE header signatures or import thunk-like data without any backing file.

 - Short lived processes that perform large RWX allocations and then spawn threads in other processes.

 - Direct syscall stubs or raw syscall invocation patterns for ntdll functions (a likely sign of attempts to bypass user-mode hooks).

 - Memory regions that appear to contain decrypted payloads (sudden entropy changes, high entropy in anonymous pages immediately after an allocation).

 - Unusual parent-child provenance: a tooling/process that normally doesn’t manage other processes suddenly opening handles and allocating memory.

## 🦠 Malware & Threat Actors Documented Abusing NtAllocateVirtualMemory

### **Ransomware**
 - Agenda (Qilin) Ransomware
 - BabLock Ransomware
 - Hive Ransomware

### **Commodity Loaders & RATs**
 - Bliseter Loader
 - GuLoader
 - IcdedID

### **APT & Threat Actor Toolkits**
 - Cozy Bear
 - Lazarus Group
 - Wicked Panda

### **Red Team & Open Source Tools**
 - Brute Ratel 
 - Cobalt Strike
 - PoshC2

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `NtAllocateVirtualMemory`.

## 🧵 `NtAllocateVirtualMemory` and Friends
`NtAllocateVirtualMemory` usually appears adjacent to a small family of related APIs and syscalls: 
 - `VirtualAlloc`, `VirtualAllocEx` (user-mode wrappers)
 - `ZwAllocateVirtualMemory` (kernel-mode variant)
 - `NtWriteVirtualMemory`. `WriteProcessMemory` (for staging payloads)
 - `NtProtectVirtualMemory`, `VirtualProtectEx` (to flip protections)
  - `NtCreateThreadEx`, `CreateRemoteThread`, `QueueUserAPC`, `SetThreadContext`+`ResumeThread` (for execution)
  
  And then there are functions used for process access like `OpenProcess` or `NtOpenProcess`. If you see these names grouped together in a sequence, you’re likely looking at injection or in memory execution behavior.

## 📚 Resources
- [Microsoft Docs: NtAllocateVirtualMemory](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!