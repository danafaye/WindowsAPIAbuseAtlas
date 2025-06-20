### 🧪 EnumProcessModules  
### 🚀 Executive Summary  
**EnumProcessModules**, exposed via **psapi.dll**, returns a list of module handles (DLLs) loaded into the address space of a specified process. When given a valid process handle, it lets the caller iterate through loaded libraries and inspect their names, base addresses, and memory ranges.

This capability is critical for legitimate tools like Task Manager and Process Explorer, but it's also incredibly valuable for adversaries doing module discovery before making surgical moves. Attackers rely on it to spot security tools, debuggers, or sandbox DLLs injected into processes. This reconnaissance guides stealthy malware decisions around evasion, patching, code injection—and which process is safest or most advantageous to inject into next.


### 🔍 What is EnumProcessModules?  
`EnumProcessModules` takes a handle to a target process and fills an array with module handles for every DLL loaded in that process’s memory space. These handles can then be used with other APIs like `GetModuleFileNameEx` or `GetModuleInformation` to pull more details—like full file paths, base addresses, and sizes.

Under the hood, the function walks through the Process Environment Block (PEB) and its loader data structures, which track all loaded modules as linked lists. This makes it a solid, reliable way to enumerate exactly what DLLs are in use.

Because it only needs a handle with `PROCESS_QUERY_INFORMATION` and `PROCESS_VM_READ` rights, attackers who can get a handle to a target process—even their own—can quickly grab a full snapshot of its loaded modules. This helps them profile the environment and plan next moves.

### 🚩 Why It Matters  
- **Module Enumeration & Recon**: `EnumProcessModules` from `psapi.dll` lets attackers list every DLL loaded in a target process. This reveals the exact set of libraries running, including security tools, debuggers, or sandbox DLLs. It’s a quick way to profile the environment and figure out what’s watching.

- **Injection & Patch Prep**: With details like base addresses and sizes, attackers can zero in on exact spots inside DLLs or system libraries for code injection or patching. This makes their tweaks surgical and harder to spot.

- **Anti-Analysis & Evasion**: By mapping out loaded modules first, attackers can dodge or bypass hooks and instrumentation security tools leave behind. This keeps their activity under the radar while they hook, unhook, or mess with memory.

### 🧬 How Attackers Abuse It  
Malware leverages `EnumProcessModules` to get a clear view of which DLLs are loaded—whether in its own process or others it’s targeting. By enumerating these modules, attackers can spot security products by name or file path, giving them early warning about what defenses are in play. They can also detect if they’re running inside a debugger or sandbox, which often leads malware to alter its behavior or just bail out entirely. Beyond reconnaissance, `EnumProcessModules` helps pinpoint exact modules for injection, hooking, or memory patching. This function is a critical first step in many stealthy malware operations, setting the stage for precise modifications and evasions within the Windows environment.


### 🛡️ Detection Opportunities  

### 🔹 YARA

Check out some sample YARA rules here: [EnumProcessModules.yar](./EnumProcessModules.yar).

> **Heads up:** These rules are loosely scoped and designed for hunting and research. They're **not** meant for production detection systems that require low false positives. Please test and adjust them in your environment.

### 🔸 Behavioral Indicators

- Flag any unexpected calls to `EnumProcessModules` coming from processes or contexts where module enumeration isn’t typical—like command-line tools suddenly poking around other critical system processes, or user apps that don’t normally inspect loaded modules. These out-of-place calls often signal reconnaissance activity or malware probing its environment.

- Watch for patterns where `EnumProcessModules` is quickly followed by calls to change memory protections (`VirtualProtect`, `NtProtectVirtualMemory`) or injection-related APIs (`WriteProcessMemory`, `CreateRemoteThread`). This combo is a strong indicator that the module enumeration is part of an injection or code patching attempt, not just harmless process introspection.

- Build or leverage threat intelligence lists of known security product and sandbox DLL names. Correlate module enumeration results against these lists to detect when malware is actively hunting for defenses or sandbox environments. Identifying these “red flags” early can help defenders spot stealthy malware that’s trying to adapt or hide.

### 🦠 Malware & Threat Actors Documented Abusing EnumProcessModules

### **Ransomware**
- LockBit  
- REvil (Sodinokibi)  
- Conti  

### **Commodity Loaders & RATs**
- Cobalt Strike  
- Remcos RAT  
- TrickBot  

### **APT & Threat Actor Toolkits**
- APT41  
- FIN7 (Carbanak)  
- Turla  

### **Red Team & Open Source Tools**
- SharpSploit  
- Covenant  
- Donut  

### 📚 Resources  
- Microsoft Docs: [`EnumProcessModules`](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocessmodules)  
