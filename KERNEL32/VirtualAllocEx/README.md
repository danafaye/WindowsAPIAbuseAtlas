# ⚙️ VirtualAllocEx: The Classic Cornerstone of Process Injection

## 🚀 Executive Summary
`VirtualAllocEx` doesn’t just allocate memory. It opens the door. As a remote memory allocation API, it gives one process the ability to carve out space inside another, laying the groundwork for classic process injection. While defenders often focus on execution APIs like `CreateRemoteThread` or `SetThreadContext`, they’re only part of the picture. The real action starts here, with memory quietly marked as `PAGE_EXECUTE_READWRITE`, waiting for shellcode. This API isn’t flashy, but it’s everywhere: from red team toolkits to nation-state malware, `VirtualAllocEx` is the quiet operator that makes remote code execution possible.

## 🔍 What is VirtualAllocEx?
`VirtualAllocEx` is a handy API from `kernel32.dll` that lets one process allocate memory inside another process’s address space. It’s totally legit and shows up in all sorts of tools: debuggers, profilers, even some automation frameworks, whenever they need to prepare a spot in memory to drop in code or data. Unlike the regular `VirtualAlloc`, which sticks to the calling process, this one takes a handle to a target process, making it useful (and powerful) when working across process boundaries. Of course, that power cuts both ways.

## 🚩 Why It Matters
Remote memory allocation gives attackers something they usually don’t have: a trusted home for their code. Instead of spawning a new process that sticks out like a sore thumb, they inject into one that’s already running and already allowed to do sensitive things. Think browsers, AV agents, or system tools. By allocating memory inside these processes, adversaries gain stealth, persistence, and access to privileged capabilities without triggering as many alarms. It’s not just about hiding. It’s about operating with elevated trust. Whether launching shellcode, unpacking a stager, or hijacking execution flow, this technique gives them the flexibility to execute malicious logic where defenders least expect it, wrapped in the credibility of a legitimate binary.

## 🧬 How Attackers Abuse It
Attackers usually start with `VirtualAllocEx` to carve out space inside the target process, quietly setting the stage. Then they drop in their payload using `WriteProcessMemory`, effectively loading their code into someone else's address space. From there, they pick an execution method: `CreateRemoteThread` for the direct route, APC queuing for stealthier launches, or thread hijacking if they want to avoid creating new execution artifacts altogether. You’ll see this play out in so many different malware families, it’s difficult to name them all. Favorite targets for injection include browsers, explorer.exe, and even AV processes.  This gives attackers a trusted context to exfiltrate data or run commands unnoticed. The combination of stealth, flexibility, and access to legitimate process privileges makes this one of the most widely abused techniques in modern post-exploitation.

## 👀 Sample Behavior
Spotting malicious use of remote memory allocation means looking past the API calls and into how and why they’re being used. Legitimate tools like debuggers or automation frameworks might use `VirtualAllocEx` and `WriteProcessMemory`, but they usually do it in predictable contexts, like being launched from a dev environment or signed, well-known binaries. Malicious use, on the other hand, tends to show up in weird places: unsigned binaries in temp folders, strange parent-child process chains, or sudden memory allocations targeting high-value processes like browsers or AVs. Timing also matters. If allocation is followed immediately by thread creation or APC injection into a security tool, that’s a huge red flag. Cross-process injection into unrelated or high-privilege processes should always be treated with suspicion, especially if the caller has no business doing memory manipulation at all. Context is everything.

## 🛡️ Detection Opportunities

### 🔹 YARA

Here are some sample YARA rules to detect suspicious use of `VirtualAllocEx`:

See [VirtualAllocEx.yar](./VirtualAllocEx.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🔹 Behavioral Indicators
Behavioral indicators are often the best way to separate malicious remote memory allocation from legitimate use. Defenders should watch for unexpected process relationships:
 
 - low-privilege or unknown process suddenly allocating memory and injecting code into a high-value target such as a browser, explorer.exe, or an AV process. 
 - sudden spikes in remote thread creation (CreateRemoteThread) or queued APCs following memory allocation are red flags, especially when the parent process isn’t a known system or trusted tool
 - Rapid, repeated allocations combined with writes to another process’s memory space, often followed by unusual network activity or suspicious command execution. 
 
 Since many legitimate tools operate in predictable patterns or specific user contexts, anomalies in timing, origin, or target process are critical to catch. Ultimately, defenders who correlate these low-level API behaviors with process lineage, signed binary validation, and runtime context gain a significant advantage in detecting this classic post-exploitation technique before it escalates.


## 🦠 Malware & Threat Actors Documented Abusing VirtualAllocEx

If malware needs to live inside someone else’s process, odds are it’s starting with `VirtualAllocEx` and `WriteProcessMemory`. This combo is the bread and butter of remote code injection. It shows up in loaders, stealers, ransomware, APT toolkits, red team frameworks, pretty much everything, you name it.  That said, not *every* malware uses it. Some go the hollowing route, others hijack threads or execute entirely within their own process, but when the goal is stealthy execution in a high-value target, this is usually the first move. It’s not flashy, but it works. That’s why it’s still everywhere.

### **Ransomware**
 - Agenda
 - CryptoGuard
 - Ryuk

### **Commodity Loaders & RATs**
 - DuplixSpy RAT
 - Quasar RAT
 - Remcos RAT

### **APT & Threat Actor Toolkits**
 - APT10 (Stone Panda)
 - APT31 (Hurricane Panda)
 - APT28 (Fancy Bear)
 - (Likely most)

### **Red Team & Open Source Tools**
 - Empire 
 - NumPlant
 - Sliver
 - (Many many more)

> **Note:** This list isn’t exhaustive. Many modern malware families and offensive security tools use `VirtualAllocEx` for stealth and evasion.

## 🧵 `VirtualAllocEx` and Friends
`VirtualAllocEx` is the go-to for remote memory allocation, but it’s not the only player in the game. APIs like `VirtualAlloc` do the same thing, just in the current process. For attackers staying local, that’s usually enough. If they want even lower-level control, they’ll reach for `NtAllocateVirtualMemory`, the syscall version that skips some of the logging and overhead. Then there’s `MapViewOfFile` and `NtMapViewOfSection`, which let attackers share memory between processes without writing data directly—great for stealthy injections or unpacking payloads. You’ll also see `HeapCreate` and `HeapAlloc` pop up occasionally in DIY allocators or weird evasive loaders. The functionality overlaps, but the context matters: are they setting up shellcode, unpacking a stager, or just allocating scratch space? When these APIs show up in unusual places or together with thread creation, DLL loading, or process injection routines, it’s usually a sign something shady’s cooking.

## 📚 Resources
- [Microsoft Docs: VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
- [MITRE: Process Injection](https://attack.mitre.org/techniques/T1055/002)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!