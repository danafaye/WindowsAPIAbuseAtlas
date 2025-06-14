# NtMapViewOfSection

## 🚀 Executive Summary
`NtMapViewOfSection` is a native Windows API from `ntdll.dll` that’s a key player in stealthy process injection techniques like process hollowing and reflective DLL loading. It lets attackers map section objects into another process’s memory space, bypassing more commonly watched APIs like `VirtualAllocEx` and `WriteProcessMemory`. Because it can map executable memory across processes with low visibility to most security tools, it’s a favorite for sophisticated malware authors. While legitimate apps sometimes use it for shared memory, seeing this API used alongside suspicious behavior, like mapping into suspended processes or right after `NtUnmapViewOfSection` calls, is a strong red flag that defenders should watch closely.

## 🚩 Why It Matters
Defenders need to understand `NtMapViewOfSection` because it’s one of those quiet APIs that attackers love. It lets them map memory—often containing shellcode or an entire PE—into a process without touching the usual, noisy injection paths like `WriteProcessMemory` or `LoadLibrary`. Since it's low-level NTAPI, a lot of EDRs just don’t see it, especially if you're only watching for high-level calls. That makes it perfect for stealthy payload delivery and execution. If you're not hunting for this kind of activity—like odd section mappings or sketchy memory permissions—you’re missing a big part of the picture.

## 🧬 How Attackers Abuse It  
Attackers abuse `NtMapViewOfSection` to quietly inject code by mapping a section object—created with `[NtCreateSection](../NtCreateSection/README.md)` or hijacked via `NtOpenSection`—into the memory space of a target process. The section can hold raw shellcode, a DLL, or even a full PE image, and it’s mapped with execute permissions to prep for runtime. From there, execution kicks off with `NtCreateThreadEx`, a thread hijack, or APC. Because none of the usual APIs show up—no `WriteProcessMemory`, no `LoadLibrary`—this entire flow flies under the radar of many detection stacks. It’s clean, native, and blends in with normal OS behavior, which is exactly why it shows up in everything from commodity malware to advanced post-exploitation frameworks.

## 🧵 Sample Behavior: Reflective DLL via Section Mapping  
One common use case: reflective DLL injection into `explorer.exe` post-RCE. The attacker creates a section with `[NtCreateSection](../NtCreateSection/README.md)`, writes in a custom DLL stub, and maps it into `explorer` with `NtMapViewOfSection`. No high-level memory writes, no obvious injection API calls. To kick things off, they use `NtCreateThreadEx` to start execution inside the mapped view. Because the DLL never touches disk and the injection uses only native APIs, EDRs watching for file-based loads or standard injection calls miss it completely. This pattern shows up in tools like Cobalt Strike and is increasingly common in fileless post-exploitation chains.

## 🛡️ Detection Opportunities

### 🔹 YARA

Check out some sample YARA rules here: [NtMapViewOfSection.yar](./NtMapViewOfSection.yar).

> **Heads up:** These rules are loosely scoped and designed for hunting and research. They’re **not** meant for production detection systems that require low false positives. Please test and adjust them in your environment.

### 🔸 Behavioral Indicators

Monitoring these behaviors together can help defenders catch stealthy code injection attempts that leverage `NtMapViewOfSection` and related NT native APIs:

## 🔍 Behavioral Indicators of `NtMapViewOfSection` Abuse

- Creation of section objects (`[NtCreateSection](../NtCreateSection/README.md)`) with execute permissions (`PAGE_EXECUTE_READWRITE` or `PAGE_EXECUTE_WRITECOPY`), especially if backed by pagefile or memory rather than a mapped file.
- Mapping those sections into remote processes using `NtMapViewOfSection` with executable access.
- Threads created in processes immediately after section mapping, particularly if using low-level APIs like `NtCreateThreadEx` instead of standard thread creation calls.
- Absence of common injection API calls (`WriteProcessMemory`, `VirtualAllocEx`, `CreateRemoteThread`) alongside suspicious memory mappings.
- Sections mapped with names or handles that don’t correlate with legitimate modules or known DLLs.
- Processes showing executable memory regions mapped from section objects rather than files on disk.
- Sudden or unexplained memory mappings with execute permissions in processes that don’t normally load dynamic code.
- Parent-child process relationships where the child process has suspicious mapped sections and threads started shortly after.
- Anomalous thread context changes or APC injections targeting mapped section regions.

## 🦠 Malware & Threat Actors Documented Abusing NtMapViewOfSection

Below is a curated list of malware families, threat actors, and offensive tools known to abuse or patch `NtMapViewOfSection` for defense evasion.  

For the latest technical write-ups, search for the malware or tool name together with "NtMapViewOfSection" on reputable security blogs, threat intelligence portals, or simply google. (Direct links are not included to reduce maintenance.)

### Ransomware
Agenda
LockPos
MailTo
Magniber

### Commodity Loaders & RATs
AsyncRAT
DarkVision RAT
Formbook
PlugX
QuasarRAT
Remcos RAT

### APT & Threat Actor Toolkits
APT 38 (BeagleBoyz, Bluenoroff, Stardust Chollima, COPERNICIUM)
APT 41
Gelsemium 

### Red Team & Open Source Tools
Cobalt Strike
SharpSploit
Sliver
Metasploit
Empire


> **Note:** This list isn’t exhaustive. Many modern malware families and offensive security tools use `NtMapViewOfSection` for stealth and evasion. As awareness grows, expect even more to adopt it.

## 🧵 `NtMapViewOfSection` and Friends


## 📚 Resources
[NTAPI Undocumented Functions](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtMapViewOfSection.html)
[NtQueueApcThread](../NtQueueApcThread/README.md)
[NtCreateSection](../NtCreateSection/README.md)


> **Know of more?**  
> Open a PR or issue to help keep this list up to date!

