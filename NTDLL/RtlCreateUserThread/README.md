# 🪡 RtlCreateUserThread: Quiet Threading

## 🚀 Executive Summary
`RtlCreateUserThread` is the covert thread starter for attackers who need to move quietly inside Windows. By sidestepping the typical Win32 APIs, it lets malware inject and run code in remote processes with minimal noise and fewer hooks to trip alarms. This internal, low-level API is a favorite for stealthy process injection and memory-only payloads—making it a critical piece of the attacker’s toolkit and a must-know for defenders hunting silent thread creation.

## 🔍 What is RtlCreateUserThread?
`RtlCreateUserThread` is an internal function from `ntdll.dll` that creates a thread in a remote or local process without relying on the Win32 API layer. It’s used legitimately by components like the WoW64 subsystem to support 32-bit execution on 64-bit systems, and by system-level tools that need low-level control over thread creation. Its design allows for precise thread initialization in native environments where higher-level APIs aren't suitable.

## 🚩 Why It Matters
`RtlCreateUserThread` flies under the radar. It skips the Win32 layer, dodging common userland hooks and slipping past EDR visibility. It works cleanly in native and WoW64 environments, making it a go-to when [CreateRemoteThread](../../KERNEL32/CreateRemoteThread/) is too noisy or unreliable. If you’re not looking for it, you’ll miss the thread and the payload it launches.

## 🧬 How Attackers Abuse It
After dropping shellcode with [VirtualAllocEx](../../KERNEL32/VirtualAllocEx/) and [WriteProcessMemory](../../KERNEL32/WriteProcessMemory/), attackers use `RtlCreateUserThread` to kick off execution inside a remote process. Quietly. No Win32 calls, no easy hooks, just a thread launched straight from ntdll. It’s built for stealthy injections, reflective loaders, and memory-resident payloads that don’t want to be seen. The less noise, the more damage. This API helps keep it that way.

## 🛡️ Detection Opportunities

Here are some sample YARA rules to detect suspicious use of `RtlCreateUserThread`:

See [RtlCreateUserThread.yar](./RtlCreateUserThread.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
Malware doesn’t import `RtlCreateUserThread` directly. It grabs it at runtime using `GetProcAddress`, often via a `LoadLibrary("ntdll.dll")` or inline shellcode that walks the export table. This lets it avoid import table analysis and blend in with legitimate use of ntdll. You won’t find it in static IATs; you’ll need to hunt for dynamic resolution patterns.

 - Calls to `GetProcAddress` or `LdrGetProcedureAddress` resolving `RtlCreateUserThread` from `ntdll.dll`
 - Thread creation in remote processes without [CreateRemoteThread](../../KERNEL32/CreateRemoteThread/) or NtCreateThreadEx in telemetry ... especially when preceded by [VirtualAllocEx](../../KERNEL32/VirtualAllocEx/) and [WriteProcessMemory](../../KERNEL32/WriteProcessMemory/)
 - Shellcode or reflective DLLs that resolve only low-level APIs, skipping higher-level Win32 wrappers entirely
 - Threads with unusual start addresses in writable or executable memory regions (especially in remote processes)
 - Missing or minimal parent-child thread telemetry (EDRs may not trace threads from RtlCreateUserThread cleanly)
 - Process memory scanners can catch injection if they monitor for newly executable memory that coincides with thread creation

## 🦠 Malware & Threat Actors Documented Abusing RtlCreateUserThread
`RtlCreateUserThread` shows up across the spectrum from red team toolkits to advanced malware loaders. It’s favored in operations where stealth matters more than portability, and it’s been used to inject code into everything from user-mode processes to system level targets. You’ll find it in post-exploitation frameworks, fileless malware, and memory-resident implants that rely on low level APIs to stay quiet and persistent. Its use signals intent: evade hooks, avoid noise, and execute without tripping the usual wires.

### **Ransomware**
 - Magniber
 - Nokoyawa Ransomware
 - Phobos

### **Commodity Loaders & RATs**
 - DBatLoader
 - IcedID
 - IndigoDrop

### **APT & Threat Actor Toolkits**
 - APT29
 - APT31
 - FIN8

### **Red Team & Open Source Tools**
 - Atomic Red Team
 - Cobalt Strike
 - Merlin

> **Note:** This list isn’t exhaustive. It is certain that more modern malware families and offensive security tools use `RtlCreateUserThread` for stealth and evasion.

## 🧵 `RtlCreateUserThread` and Friends
`RtlCreateUserThread` rarely acts alone. It’s almost always paired with [VirtualAllocEx](../../KERNEL32/VirtualAllocEx/) to carve out executable memory and [WriteProcessMemory](../../KERNEL32/WriteProcessMemory/) to plant the payload. For process access, `OpenProcess` is the usual first step, granting the needed handle. While [CreateRemoteThread](../../KERNEL32/CreateRemoteThread/) and `NtCreateThreadEx` offer alternative thread creation paths, `RtlCreateUserThread` stands out by skipping Win32, but attackers often switch between these depending on the environment. Dynamic API resolution via `GetProcAddress` or `LdrGetProcedureAddress` is common, hiding imports and complicating detection. Together, these APIs form a common injection toolkit that’s critical to understand for tracking thread based code execution abuse.

## 📚 Resources
- [MITRE: Process Injection](https://attack.mitre.org/techniques/T1055/)
- [NTAPI Undocumented Functions: RtlCreateUserThread](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FRtlCreateUserThread.html)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!