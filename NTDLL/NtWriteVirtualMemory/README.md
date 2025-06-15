# NtWriteVirtualMemory

## 🚀 Executive Summary
`NtWriteVirtualMemory` is the low-level sibling of `WriteProcessMemory`—same result, less visibility. It’s not some obscure edge-case API either; this one shows up everywhere. Used in plenty of legit scenarios, sure, but malware loves it for the same reason: you can shove shellcode into a remote process, patch memory, or hijack execution flow without lighting up the usual alarms. Think process injection, tool tampering, or flying under the EDR radar. Classic abuse, stealth mode.


## 🚩 Why It Matters

- **Injection 101:** This API shows up in almost every process injection technique out there.
- **Lower profile:** Quieter than its Win32 sibling `WriteProcessMemory`, and that's exactly why malware prefers it.
- **Do anything:** Drop shellcode, patch memory, flip execution—if you can write it, you can plant it.
- **Everyone’s using it:** From script kiddies to APTs, this one’s a favorite.
- **Bypass city:** Native calls help dodge userland hooks and EDR eyes.

## 🧬 How Attackers Abuse It

Manipulating memory is fundamental to a ton of attack techniques because it’s the quickest way to bypass defenses, reshape how processes behave, and inject code that runs under the radar. Attackers start by pinpointing key processes, then flip memory protections to open writable spaces. From there, they patch security checks, hijack function calls, or drop shellcode right into a process’s address space. Owning memory like this means staying quiet, persistent, and way harder to catch.


## 🧵 Sample Behavior

 - **Patching Security Product Memory**: Attackers usually kick things off with `NtQuerySystemInformation` to find AV or EDR processes. Then it's `NtOpenProcess` to grab a handle, `NtProtectVirtualMemory` to loosen up memory permissions, and `NtWriteVirtualMemory` to do the dirty work, patch scanning routines, kill sig detection, or mess with callback functions. Clean, direct, and nasty.

 - **Modifying Process Behavior**: To mess with a running process, attackers often set up shared memory using `NtCreateSection` and `NtMapViewOfSection`, then use `NtQueryVirtualMemory` to scout for the right function or structure to hit. Once mapped, they flip permissions with `NtProtectVirtualMemory` and drop in changes using `NtWriteVirtualMemory`—patching IATs, jump tables, or slipping in custom hooks. It’s surgical, persistent, and tough to catch.

 - **Rootkit-Level Tampering**: Rootkits start by locating system DLLs with `NtQueryDirectoryFile`, then read them using `NtCreateFile` and `NtReadFile`. After that, they jump into `NtWriteVirtualMemory` to patch system calls, tweak kernel structures, or insert inline hooks. This usually goes hand-in-hand with `NtProtectVirtualMemory` to change permissions and `NtFlushInstructionCache` to make sure the CPU sees the changes.

 - **Deploying Shellcode / Position-Independent Code**: Attackers allocate RWX memory with `NtAllocateVirtualMemory`, then load their shellcode using `NtWriteVirtualMemory`. After that, they lock down permissions with `NtProtectVirtualMemory` before kicking off execution—either asynchronously with `NtQueueApcThread`, directly via `NtCreateThreadEx`, or stealthy-style through `RtlCreateUserThread`.

 - **Process hunting and injection:** Attackers use `CreateToolhelp32Snapshot` to scan running processes and zero in on their target. Then it’s `OpenProcess` to grab a handle, `VirtualAllocEx` to carve out writable memory, and `NtWriteVirtualMemory` to slip in the payload—all clean, quiet, and under the radar.


## 🛡️ Detection Opportunities

### 🔹 YARA

Check out some sample YARA rules here: [NtWriteVirtualMemory.yar](./NtWriteVirtualMemory.yar).

> **Heads up:** These rules are loosely scoped and designed for hunting and research. They're **not** meant for production detection systems that require low false positives. Please test and adjust them in your environment.

### 🔸 Behavioral Indicators

#### Process Injection Signs
- Writing across process boundaries, especially to newly allocated or executable memory  
- Typical chain: open process → allocate memory → write payload → flip permissions → create thread or queue APC  
- Threads popping up in weird places or using uncommon start routines  
- Heavy use of memory protection changes right around injection time  
- Scanning for targets with process snapshots or system queries, especially hitting security tools  
- Handles opened to unexpected processes or modules

#### Memory Tampering Signs
- Writes targeting security tools or kernel memory ranges  
- Small, surgical edits to code: patching function pointers, IAT/EAT entries, or jump tables  
- Messing with callbacks or hooks set by defense software  
- Memory protections flipped in ways normal apps don’t do  
- Flushing instruction cache right after memory writes  
- Using low-level native calls that bypass usual API monitoring  
- Reading process memory just before making targeted changes

## 🦠 Malware & Threat Actors Documented Abusing NtWriteVirtualMemory

Let’s be honest ... if there’s an attacker out there, they’re probably using `NtWriteVirtualMemory`. From script kiddies to APTs, this API is like pizza ... everyone loves it, and it shows up everywhere when you want something reliable and effective. If you’re not watching for it, you’re missing a key ingredient in the attack recipe.

### Ransomware
- BlackCat
- BlackMatter
- DarkSide
- Conti
- LockBit
- REvil

### Commodity Loaders & RATs
- AsyncRAT
- Emotet
- NjRAT
- QBot
- TrickBot

### APT & Threat Actor Toolkits
- APT29
- FIN7
- NOBELIUM
- Lazarus Group
- APT41
- Turla

### Red Team & Open Source Tools
- Cobalt Strike
- Metasploit
- Mimikatz
- PowerSploit
- Empire
- PoshC2
- Covenant
- Havoc
- Sliver

> **Note:** This list isn't exhaustive. Many modern malware families and offensive security tools use `NtWriteVirtualMemory` for code injection and memory manipulation.

## 🧵 `NtWriteVirtualMemory` and Friends
`NtWriteVirtualMemory` is just one player in a tight-knit squad of native Windows APIs that handle memory manipulation. It works alongside `NtAllocateVirtualMemory` to carve out memory, `NtProtectVirtualMemory` to change page protections, and `NtReadVirtualMemory` to peek into process memory. Attackers use this whole toolkit to pull off complex memory tricks — allocating space, writing payloads, tweaking protections, and eventually executing code stealthily. While `NtWriteVirtualMemory` does the heavy lifting of actually writing the data at the native level, in user-mode you’ll often see `WriteProcessMemory` being called instead, which is the Win32 wrapper for this operation. So keep an eye on both, since they rarely act alone in an attack chain.


## 📚 Resources
[NTAPI Undocumented Functions](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtWriteVirtualMemory.html)
[Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas) (more like this)

> **Know of more?**  
> Open a PR or issue to help keep this list up to date!