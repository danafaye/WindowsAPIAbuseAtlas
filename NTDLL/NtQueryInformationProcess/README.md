# 🔬 NtQueryInformationProcess

## 🚀 Executive Summary
`NtQueryInformationProcess` is the kind of syscall that doesn’t make noise. It makes decisions. Quiet, flexible, and deeply underestimated, it’s the API that malware calls when it wants to know exactly what it’s walking into. Need to check if a debugger’s watching? Steal a peek at a token? See who spawned you? This one call does it all, without leaving a splash in user-mode logs. It’s not flashy. It doesn’t drop shells or move laterally. But it enables all of that and more because it tells attackers exactly when and how to strike. If you’re not watching for it, you’re already behind.

## 🧠 What is NtQueryInformationProcess
`NtQueryInformationProcess` is a native Windows API that retrieves a wide range of information about a specified process. It takes in a handle to a process, a `PROCESSINFOCLASS` value indicating the type of information requested, and a buffer to receive the result. The API supports dozens of information classes, enabling queries for basic process details, memory layout, debug state, handle tables, and more. Its versatility stems from the richness of its `PROCESSINFOCLASS` enumeration, which defines the structure and semantics of the returned data. As part of the `ntdll.dll` export set, it operates at a lower level than typical Win32 APIs, making it a core building block for process introspection on Windows systems.

## 🚩 Why It Matters
`NtQueryInformationProcess` is like a lockpick with a hundred interchangeable heads. It slips past the velvet ropes of user-mode APIs and goes straight to the source; pulling back the curtain on process internals with surgical precision. Whether it’s looking for a debugger, grabbing a parent PID, or fishing for token details, this quiet syscall asks the kinds of questions that normal tools aren’t supposed to. Most defenders glance past it, thinking it’s just background noise. But in the right hands, it’s a reconnaissance engine that whispers the shape of what's coming next.

## 🧬 How Attackers Abuse It

`NtQueryInformationProcess` is a shape-shifter. What you get back depends entirely on the info class you feed it. That magic number flips the switch, unlocking different layers of the target process’s secrets. One moment you’re pulling basic IDs and memory stats, the next you’re digging into debug ports or handle tables. It’s a master keyring to the process’s hidden rooms, with each setting revealing a new angle for reconnaissance or stealthy probing. Master the codes you pass in, and you hold the keys to a thousand hidden doors inside the system’s guts.

### Debugger Detection
Attackers use `NtQueryInformationProcess` with information classes like `ProcessDebugPort` (0x7), `ProcessDebugObjectHandle` (0x1e), or `ProcessDebugFlags` (0x1f) to directly query the debug state of a target process. For example, querying `ProcessDebugPort` returns a handle to a debug port if a debugger is attached, or zero otherwise. `ProcessDebugFlags` can indicate if the process is being debugged or if debugging is hidden. By interpreting these results, malware can silently detect if it’s being debugged without relying on the noisy Win32 API `IsDebuggerPresent`, helping it evade analysis or sandbox environments.

### Parent Process Discovery
By querying `ProcessBasicInformation` (0x0), which returns a `PROCESS_BASIC_INFORMATION` structure, malware extracts the `InheritedFromUniqueProcessId` field, the parent process ID. Knowing its parent process allows malware to verify if it was launched by a legitimate system process (like explorer.exe) or by suspicious software. This helps attackers maintain stealth by blending into normal process trees or tailoring payloads depending on the execution context.

### Privilege & Token Inspection
The `ProcessToken` (0x8) information class returns a handle to the access token associated with the process. Attackers query this to inspect their current privileges and rights. This handle can be used alongside other APIs to enumerate privileges (like `SeDebugPrivilege`) or to impersonate tokens. Understanding the privilege level enables malware to decide whether privilege escalation attempts are needed or if certain actions requiring higher permissions are feasible.

### Handle Table Enumeration
`ProcessHandleInformation` (0x40) returns a list of all handles the process owns, including files, registry keys, synchronization objects, and other processes. By enumerating these handles, malware can identify if security software hooks or monitoring handles are present, or locate handles that allow direct access to sensitive resources. This assists in bypassing security controls or escalating privileges by duplicating or manipulating existing handles.

### Memory & Performance Metrics
Using `ProcessVmCounters` (0x10) or `ProcessWorkingSetWatch` (0x12), malware gathers detailed memory usage and working set information. These metrics help determine if the process is running in an emulated or sandboxed environment, which often has constrained memory or unusual paging patterns. Recognizing such environments allows malware to modify behavior (like delaying execution or remaining dormant—to avoid detection).

### Anti-debugging & Anti-analysis Flags
Certain obscure flags returned via `ProcessInformationClass` queries reveal whether kernel debugging or system-wide tracing is enabled. For instance, querying `ProcessInstrumentationCallback` (0x28) or related classes can indicate if instrumentation callbacks are hooked. These flags help malware detect deep inspection or monitoring setups and adapt by obfuscating execution or self-terminating to thwart analysis.

### Monitoring Self or Other
Malware often continuously polls process information on itself or child processes to detect interference, such as termination attempts or debugger attachment. Repeated calls to `NtQueryInformationProcess` allow dynamic response triggering evasive actions, altering control flow, or self-deleting. This makes live debugging difficult because the malware adapts in real time based on the state information retrieved.


## 🛡️ Detection Opportunities

### 🔹 YARA
Check out some sample YARA rules here: [NtQueryInformationProcess.yar](./NtQueryInformationProcess.yar).

> **Heads up:** These rules are loosely scoped and designed for hunting and research. They're **not** meant for production detection systems that require low false positives. Please test and adjust them in your environment.

### 🔸 Behavioral Indicators
 - Spam calls to debug info classes: pounding on ProcessDebugPort (0x7), ProcessDebugFlags (0x1f), or ProcessDebugObjectHandle (0x1e) is a classic tell.
 - Odd callers asking weird questions: processes poking at others without a good reason? Red flag.
 - Handle table snooping: frequent queries for ProcessHandleInformation (0x40) hint at sneaky resource scouting.
 - Stack trace ghosts: shady DLLs lurking in call stacks when this syscall fires.
 - Mix & match with anti-debug tricks: if you see NtSetInformationThread hiding threads or timing calls near it, watch out.
 - Telemetry spikes: sudden bursts of low-level queries don’t happen by accident.

## 🦠 Malware & Threat Actors Documented Abusing NtQueryInformationProcess

### Ransomware
- BlackByte
- BlueSky
- Nefilim
- Shadowpad

### Commodity Loaders & RATs
- Raspberry Robin
- SmokeLoader
- SpiceRAT
- (many many more)

### APT & Threat Actor Toolkits
 - Actor240524
 - Lazarus

### Red Team & Open Source Tools
 - Brute Ratel
 - Cobalt Strike
 - Sliver
 

> **Note:** This list isn't exhaustive. Many modern malware families and offensive security tools use `NtQueryInformationProcess` for code injection and memory manipulation.

## 🧵 `NtQueryInformationProcess` and Friends
`NtQueryInformationProcess` doesn’t roam alone in the shadows. It's part of a family of low-level syscalls that pry into process secrets. APIs like `ZwQueryInformationProcess` (its near twin), `NtQueryInformationThread`, and `NtQuerySystemInformation` offer similar backdoor access to thread states, system-wide snapshots, and process details. Each one slices the Windows internals from a different angle: threads, handles, modules, or system objects, giving attackers a toolkit of quiet probes to map and manipulate the OS. Understanding this suite means seeing the whole battlefield, not just a single trench.

## 📚 Resources
 - Microsoft: [NtQueryInformationProcess](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)
 - MITRE: [Native API](https://attack.mitre.org/techniques/T1106/)
 - [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas) (more like this)

> **Know of more?**  
> Open a PR or issue to help keep this list up to date!