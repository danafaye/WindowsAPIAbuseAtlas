# 🛠️ EnumProcesses: 

## 🚀 Executive Summary
`EnumProcesses` is a userland reconnaissance primitive masquerading as a diagnostic tool. Frequently used by legitimate system utilities and performance monitors, this API quietly returns a list of active process IDs.  There is no kernel access required, no elevated privileges necessary. In attacker workflows, it’s the opening move in runtime awareness: a fast, low-noise way to ask, “What’s alive?” without tipping off defenders.

Malware routinely leverages EnumProcesses in the first moments of execution to scan the landscape for EDRs, sandboxes, or security tools. The output is often fed directly into conditional branching logic, allowing payloads to adapt, hide, or self-terminate based on who’s watching. On its own, it doesn’t seem dangerous. But when paired with APIs like OpenProcess, GetModuleBaseName, or ReadProcessMemory, it forms the backbone of process fingerprinting, selective targeting, and eventual code injection.

Defenders should understand that EnumProcesses is not inherently malicious, but its context is. When used outside of diagnostics, with suspicious timing, or in rapid-fire stacks aimed at process mapping, it signals the beginning of an adversary’s runtime kill chain. From ransomware to RATs, red team frameworks to APT implants, this API shows up early and often, not because it’s loud, but because it works.


## 🔍 What is EnumProcesses?
`EnumProcesses` is a system diagnostic API designed to help software inventory, security tools, and administrators keep track of what’s running on a machine. It provides a snapshot of active process IDs, giving visibility into system activity **without requiring kernel access**. Antivirus software, task managers, and performance monitors routinely call `EnumProcesses` to populate dashboards, detect unknown or suspicious applications, or establish baselines of normal behavior. In enterprise environments, endpoint agents may use it as part of health checks or threat hunting telemetry, scanning for unauthorized processes or policy violations. It's a lightweight, user-mode way to ask, “Who’s here?”, and often the first step in understanding system state from a userland perspective.

Note: Unlike some of the other Enum* APIs like [EnumSystemLocalesW](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/KERNEL32/EnumSystemLocalesW), which accept a cuntion pointer to be caled for each item, `EnumProcesses returns a flat buffer of process IDs.  This means the caller is responsible for iterating over it and implementing their own callback pattern (if that's what they want to do).

## ⭐ Important Historical Note
While commonly referred to as `EnumProcesses`, modern Windows systems resolve this function under the name `K32EnumProcesses`, as part of a broader migration of process-related APIs from `psapi.dll` to `kernel32.dll`. Introduced in Windows Vista, the `K32` prefixed variants reflect Microsoft’s effort to consolidate functionality into core system libraries. Despite the aliasing, imports observed in malware or tools will often list `K32EnumProcesses`, not `EnumProcesses` a subtle but crucial detail for reverse engineering and detection. Analysts writing YARA rules or inspecting import tables should account for this name shift to avoid missing behavioral links.

## 🚩 Why It Matters
`EnumProcesses` is one of the first steps in process reconnaissance. Whether you're a red teamer mapping out viable targets for injection or a blue teamer scanning for anomalies in the runtime landscape, this API is where it often starts. On its own, `EnumProcesses` just hands back a list of process IDs, but paired with `OpenProcess`, `GetModuleBaseName`, or `ReadProcessMemory`, it becomes a powerful lens into what’s running, where, and why. Malware uses this to identify security tools, parent/child chains, or memory layouts worth hijacking. Defenders use it to catch suspicious modules, unknown parentage, or signs of process tampering. Understanding how this enumeration fits into both attack chains and analysis workflows is important because spotting its use (and what comes next) is often the difference between seeing malware start and catching it early.

## 🧬 How Attackers Abuse It
In malicious hands, `EnumProcesses` is a surgical tool for runtime awareness. Malware leverages it early in execution to quietly sweep the system for high-value or high-risk processes, security products, EDR agents, sandbox monitors, or rival implants. It typically runs in combination with `OpenProcess`, `EnumProcessModules`, `GetModuleBaseName`, or `QueryFullProcessImageNameW` to fingerprint each PID and build a behavioral map of the environment. This intel is then used to trigger conditional execution: evade if certain tools are running, go dormant in sandboxed environments, or pivot only if specific parent-child relationships are detected (like explorer.exe or winlogon.exe). 

In more advanced payloads, `EnumProcesses` is a precursor to process hollowing, token theft, or handle hijacking, as it helps attackers identify injection targets that offer privilege or stealth. 


## 🛡️ Detection Opportunities

Here are some sample YARA rules to detect suspicious use of `EnumProcesses`:

See [EnumProcesses.yar](./EnumProcesses.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - **Process Sweep at Startup**: Malware that immediately calls `EnumProcesses` (or wraps it via `CreateToolhelp32Snapshot`) shortly after launch, especially with no visible UI or user interaction is likely profiling its environment, not performing a user-driven task.
 - **Followed by Process Name/Path Resolution**: Look for tight sequences involving `EnumProcesses + OpenProcess + GetModuleBaseName / QueryFullProcessImageNameW`. This stack is a strong signal of PID-to-process identity resolution, typically used for antianalysis or target selection.
 - **Selective Targeting or Conditional Logic**: Branching behavior where execution paths change based on the presence of specific process names (like procmon.exe, windbg.exe, cmd.exe, chrome.exe, MsMpEng.exe) indicates the API is being used to evade or adapt to its environment (like behaving differently in a sandbox) or has configured staging logic.
 - **Used in Sandboxed Environment Checks**: Enumeration that detects short PID lists, single-threaded environments, or virtualized process trees suggests sandbox evasion. Malware may self-terminate or alter behavior when too few processes are detected.
 - **Enumeration Preceding Process Injection**: EnumProcesses abuse often leads into injection or hollowing. If the output feeds into suspicious calls like `WriteProcessMemory`, `VirtualAllocEx`, `CreateRemoteThread`, or `NtQueueApcThread`, it’s no longer reconnaissance. It’s a setup move.
 - **Used by Parent but Not Child**: In staged malware, droppers or loaders may enumerate processes to ensure the child payload launches in the right context (explorer.exe, winlogon.exe).
 - **Accompanied by Thread or Handle Inspection**: Enumeration followed by `NtQuerySystemInformation`, `NtQueryInformationProcess`, or `EnumThreads` can indicate deep inspection, often used in credential theft, unhooking, or rootkit setups.
 - **Out-of-Place Enumeration**: Legitimate software tends to enumerate during system diagnostics or monitoring. Seeing these calls in installers, macros, or unrelated utilities (image viewers, audio tools) is anomalous and suspicious.

## 🦠 Malware & Threat Actors Documented Abusing EnumProcesses
`EnumProcesses` shows up again and again in malware, not because it's flashy, but because it's reliable and doesn't require any special privileges. It's the reconnaissance workhorse that quietly builds a list of running PIDs, forming the backbone of process discovery in everything from evasive loaders to post-exploitation toolkits. Whether malware is searching for security products, identifying high-value targets, or prepping for injection, this call often comes early. And while the behavioral indicators and API pairings listed here cover common abuse patterns, they’re far from exhaustive, attackers continually mix, layer, and repackage these primitives in new ways.

### **Ransomware**
- Cuba
- Djvu/Stop

### **Commodity Loaders & RATs**
- EvilBunny
- NetSupport RAT
- ShaddowPad

### **APT & Threat Actor Toolkits**
- APT38
- APT41
- Lazarus

### **Red Team & Open Source Tools**
- Empire/PowerShell Empire
- Metasploit
- PoshC2

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `EnumProcesses` for stealth and evasion.

## 🧵 `EnumProcesses` and Friends
Like so many of the APIs in the Windows API Abuse Atlas, `EnumProcesses` rarely operates alone. It provides a top-level snapshot of active PIDs, and it’s often the first step in a chain paired with `OpenProcess` to obtain handles, then followed by `EnumProcessModules`, `GetModuleBaseName`, or `QueryFullProcessImageName` to resolve process identity and loaded binaries. For more granular inspection, malware may pivot to `NtQuerySystemInformation`, particularly with `SystemProcessInformation` or `SystemHandleInformation`, to dig deeper into process internals or identify cross-process access opportunities. When full context is needed, `CreateToolhelp32Snapshot` serves as a versatile alternative, often paired with `Process32First` and `Process32Next`. These clusters of calls, especially when observed in tight sequence, signal reconnaissance patterns that precede injection, evasion, or selective targeting logic. Understanding how these APIs interlock paints a clearer picture of process enumeration as a broader behavioral signature, not just a single noisy call.

## 📚 Resources
- [Microsoft Docs: EnumProcesses](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocesses)
- [MITRE ATT&CK: Process Discovery](https://attack.mitre.org/techniques/T1057/)
- [MITRE ATT&CK: Software Discovery: Security Software Discovery](https://attack.mitre.org/techniques/T1518/001/)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!