# 🕹️ NtSetInformationProcess

## 🚀 Executive Summary
`NtSetInformationProcess` is the kind of API that looks harmless until you realize how much power it actually has. It’s a behind the scenes Windows syscall that lets you quietly tweak a process’s inner settings. Things like debugging, handle inheritance, and, most infamously, instrumentation callbacks that feed data to EDRs. Attackers love it because it’s one function call away from turning off the lights for defenders without making any noise.

## 🔍 What is NtSetInformationProcess?
This API is the kernel level lever for configuring how a process behaves. You give it a process handle, specify a `ProcessInformationClass`, and hand over a data blob. Windows then updates internal structures accordingly. It’s basically `SetProcessInformation`’s darker, older sibling—the one that doesn’t bother with guardrails. Depending on the class you pass, it can do everything from changing memory priorities to neutering instrumentation callbacks that security tools rely on.

> `ProcessInformationClass` tells `NtSetInformationProcess` what kind of data you’re passing; the `ProcessInformation` pointer must point to a blob whose format and size are defined by that class. For the (undocumented) instrumentation case (`ProcessInstrumentationCallback`), the community uses a `PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION` blob. A structure that points to a process level callback the kernel can invoke on events like module loads or thread starts. This callback is what many EDRs and sandboxes hook into for visibility, so clearing or replacing it effectively cuts off their telemetry.

```
typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
    ULONG Version;    // 4 bytes
    ULONG Reserved;   // 4 bytes (padding / unused)
    PVOID Callback;   // pointer-size 
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, *PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;
```

## 🚩 Why It Matters
Because this is where the game of “who sees what” gets decided. When malware uses `NtSetInformationProcess`, it’s often to blind telemetry systems or sidestep hooks. EDRs typically rely on instrumentation callbacks to trace behavior turning those off means the malware can inject, hollow, or decrypt payloads in peace. It’s not loud, it’s not messy, and it leaves defenders staring at a gap in their data wondering why things went quiet.

## 🧬 How Attackers Abuse It
`NtSetInformationProcess` is most useful to attackers when they want to change what the system tells you is happening. The classic move is the `ProcessInstrumentationCallback` dance: attackers call `NtSetInformationProcess` to modify or remove the callbacks that the kernel or user mode instrumentation layer invokes when interesting events happen (module loads, thread starts, or similar). Pull those callbacks out from under an EDR and you don’t need to be particularly clever; you just turn off the feed and perform noise making actions (injection, decryption, dumping credentials) in quasi silence.

There are a few concrete flavors of this abuse:

• **Zero and go**: the attacker replaces or zeroes the instrumentation callback entries for the target process, does the dirty work (injects, writes memory, spawns stealthy children), then sometimes restores the original pointers. If you see a rapid sequence of “set info → heavy internal activity → set info back,” that’s often malicious choreography designed to leave as few breadcrumbs as possible.

• **Replace-and-redirect**: instead of nuking callbacks, an attacker might replace them with a stub that silently swallows events or reports benign looking activity. This is sneakier. Defenders still get callbacks, but the data is useless or misleading.

• **Timing attacks for sandbox evasion**: sandboxes and detonation engines rely on instrumentation to observe malicious behaviours. Malware will probe whether callbacks are present; if they are, it acts calm (sandbox yields “benign” trace). If it can remove or silence them, it proceeds with full hostile behavior. The cadence is check callbacks, silence & run. It is a telltale sandbox evasion pattern.

• **Privilege and handle tricks**: you don’t always need `SYSTEM`. If the running code can obtain a handle with `PROCESS_SET_INFORMATION` (or exploit SeDebug/other privileges), it can call `NtSetInformationProcess`. That’s why post compromise loaders and stealers (which frequently already run with elevated handles inside the victim environment) like this API: it’s another thing they can do while they already have code execution inside a process.

• **Combined techniques**: silence alone isn’t the whole attack, it’s an enabler. You’ll often see `NtSetInformationProcess` used in combination with process injection, reflective DLL loading, process hollowing, or on the fly patching of in memory APIs (especially patching `EtwEventWrite` or EDR DLL hooks). The syscall reduces observability while another routine does the actual persistence or data exfiltration.

## 🛡️ Detection Opportunities
Catching `NtSetInformationProcess` abuse is all about watching what happens before and after. Look for unexpected calls to the API from processes that shouldn’t need it (office apps, browser helpers, loaders). Correlate the call with sudden silencing of telemetry like no more ETW events, no DLL loads, no thread starts. Sysmon, ETW Threat Intelligence, or kernel callbacks can all help expose it. And if you see ProcessInstrumentationCallback getting zeroed out, that’s practically a confession note.

Here are some sample YARA rules to detect suspicious use of `NtSetInformationProcess`:

See [NtSetInformationProcess.yar](./NtSetInformationProcess.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators

 - A process calling `NtSetInformationProcess` followed by a sudden drop in ETW or telemetry events.
 - Presence of `ProcessInstrumentationCallback` or similar class IDs in memory patterns.
 - Memory regions associated with monitoring DLLs (EDR user mode hooks) being unhooked shortly after the call.
 - Suspicious child processes spawned with no corresponding telemetry events.
 - Injection or hollowing activity occurring within seconds of the API being called.

## 🦠 Malware & Threat Actors Documented Abusing NtSetInformationProcess

### **Ransomware**
 - Pandora

### **Commodity Loaders & RATs**
 - Lumma Stealer (LummaC2)

### **APT & Threat Actor Toolkits**
 - Thread Group 3390

### **Red Team & Open Source Tools**
 - 

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `NtSetInformationProcess`.

## 🧵 `NtSetInformationProcess` and Friends
This syscall hangs out with a pretty shady crowd. Its close relatives include `NtSetInformationThread` (used for stealth thread manipulation), `NtSetInformationFile` (for tampering with file handles), and `NtQueryInformationProcess` (for reconnaissance). Together, they form a set of APIs that let attackers see and alter process behavior at a depth where normal security layers rarely reach.

## 📚 Resources
- [undocumented.ntinternals.net: NtSetInformationProcess](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FProcess%2FNtQueryInformationProcess.html)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!