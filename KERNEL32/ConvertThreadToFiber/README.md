# 🧪 ConvertThreadToFiber Patching

## 🚀 Executive Summary


## 🔍 What is ConvertThreadToFiber?
`ConvertThreadToFiber` transforms the current thread into a fiber, enabling it to manually switch execution between fiber contexts using `SwitchToFiber`. This isn't multitasking like you're used to; there’s no OS scheduler involved. Fibers are fully cooperative: the application controls when and where execution jumps.

### So what is a fiber?
Think of it as a lightweight execution context that lives entirely in user mode. Unlike threads, which the OS scheduler manages, fibers are cooperatively scheduled, meaning the program itself decides when to pause one fiber and resume another. They all run inside the same thread and share the same stack space unless manually configured otherwise.

In essence:
 - Threads = OS-controlled scheduling
 - Fibers = Application-controlled scheduling

No parallelism, no kernel involvement. Just context switches orchestrated by user code.

Legitimate use cases? They're niche. Fiber APIs have historically been used in game engines and some high-performance, task-switching applications—but modern designs rarely need them. That said, when something does call this API, it's worth paying attention.

## 🚩 Why It Matters
If you're in the business of understanding strange behavior that doesn’t trip the usual alarms, `ConvertThreadToFiber` is worth knowing. It’s a quiet API, no new threads, no suspicious handles, no kernel calls. Just a process suddenly deciding it wants to schedule itself. That alone should raise an eyebrow. When something takes the time to convert to a fiber, it’s often laying groundwork for execution tricks that dodge conventional monitoring. No thread creation means no thread creation alerts. No context switch means no scheduler footprint. It’s subtle, deliberate, and often a sign that something’s about to get clever.

## 🧬 How Attackers Abuse It
Malicious and suspect software reaches for `ConvertThreadToFiber` when it wants to keep things quiet. It sets the stage. Call it once, maybe early, maybe just-in-time; then starts flipping between custom execution contexts that never show up as new threads. From there, payloads can run without the usual thread telemetry, shellcode can execute from inside the process’s own stack, and control flow gets just weird enough to trip up analysts and confuse debuggers. It might seem like extra work, but the payoff is real: evasion without elevation, stealth without syscall noise, and execution that slips past thread-centric defenses like they weren’t even watching.

## 🛡️ Detection Opportunities
Catching this kind of behavior means watching for what *doesn’t* happen. No new threads, no suspicious handles, no syscalls that usually accompany execution. Most modern software spawns threads. it’s standard fare for GUIs, background tasks, even basic I/O. So when a process does real work but never calls `CreateThread` or `NtCreateThreadEx`, that’s weird. And weird is interesting. Watch for `ConvertThreadToFiber` followed by `CreateFiber` or `SwitchToFiber`, especially in software that doesn’t normally need custom scheduling. Stack pivots without thread creation? Instruction pointer changes mid-thread? Those are your tells. Fiber abuse leaves behind a strange silhouette ... execution keeps moving, but the usual footprints are missing. If something’s hopping fibers in a tax app, it's not optimizing performance. It is hiding.

### 🔸 Behavioral Indicators
 - **Unusual fiber count or fiber handles**: Monitoring for an unusually high number of fibers created inside a single thread or process, especially if not typical for that app.
 - **Repeated rapid fiber switches**: Excessive or high-frequency calls to SwitchToFiber can indicate control flow obfuscation or staged execution.
 - **Suspicious call stacks during fiber switches**: Abrupt changes in call stack context or lack of meaningful stack frames when fibers switch, which can hint at shellcode or injected code running.
 - **Absence of thread synchronization objects**: Fibers don’t require typical thread synchronization primitives (mutexes, events). A process doing parallel work without these could be fiber-based.
 - **Fiber APIs in unusual processes**: Calls to fiber-related APIs in apps or services that normally don’t use fibers, like productivity tools or system services.

## 🦠 Malware & Threat Actors Documented Abusing ConvertThreadToFiber Patching
Below is a curated list of malware families, threat actors, and offensive tools known to abuse or patch `ConvertThreadToFiber` for defense evasion.  

For the latest technical write-ups, search for the malware or tool name together with "ConvertThreadToFiber" or "ETW evasion or patch" on reputable security blogs, threat intelligence portals, or simply google. (Direct links are not included to reduce maintenance.)

### **Ransomware**
 - Earth Ammit
 - BianLian

### **Commodity Loaders & RATs**

 ### **APT & Threat Actor Toolkits**

### **Red Team & Open Source Tools**

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `ConvertThreadToFiber` for stealth and evasion.

## 🧵 `ConvertThreadToFiber` and Friends

## 📚 Resources 
* Microsoft Docs: [ConvertThreadToFiber]()
* MITRE: [Process Injection]()
* [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas) (More like this)

> **Know of more?**  
> Open a PR or issue to help keep this list up to date!
