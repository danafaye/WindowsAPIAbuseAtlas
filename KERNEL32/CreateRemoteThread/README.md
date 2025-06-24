# 🧪 CreateRemoteThread Patching

## 🚀 Executive Summary
`CreateRemoteThread` is a classic for a reason ... it’s direct, flexible, and broadly supported, making it a go-to for attackers looking to execute code in the context of another process. While often used in straightforward injection chains with `VirtualAllocEx` and `WriteProcessMemory`, it also shows up in stealthier techniques like reflective DLL loading, thread hijacking, and executing payloads staged in suspended or trusted processes. Its reliability makes it popular across commodity malware, APT toolkits, and red team frameworks alike. But defenders have taken note, and its predictability has led to a wave of evasive tradecraft: patching the API, swapping in quieter alternatives like `NtCreateThreadEx`, or avoiding thread creation altogether. This entry explores both how `CreateRemoteThread` works and how attackers work around it—giving defenders a broader lens to catch what might otherwise slip through.


## 🔍 What is CreateRemoteThread?
`CreateRemoteThread` allows a process to create a thread in the address space of a different process. This API is commonly used for executing code remotely after memory has been allocated and populated, often via `VirtualAllocEx` and `WriteProcessMemory`. While it has limited use in legitimate applications—primarily in debuggers—it is widely used in malware and offensive tooling to inject DLLs or shellcode into other processes. Its presence is a strong signal of process injection and remote execution techniques.

## 🚩 Why It Matters
This API is included in the Windows API Abuse Atlas due to its frequent use in process injection, but also because of its versatility in less conventional tradecraft. While it's commonly used to execute shellcode or load DLLs into remote processes via `VirtualAllocEx` and `WriteProcessMemory`, `CreateRemoteThread` has also been observed in more nuanced techniques—such as executing **reflective DLL loaders directly from memory, triggering payloads staged in suspended or benign processes, or chaining with thread hijacking** for stealthier execution. Its broad compatibility and reliability make it attractive to both commodity malware and advanced threat actors employing modular or fileless payloads.

## 🧬 How Attackers Abuse It
Beyond the typical injection and execution, attackers use `CreateRemoteThread` in more subtle ways to avoid detection. This includes triggering payloads that have been quietly staged inside suspended or benign processes, allowing malicious code to run under the cover of trusted applications. Some attackers chain thread creation with thread hijacking techniques, minimizing the footprint by reusing existing threads rather than creating new ones. These variations increase stealth and complicate detection, making `CreateRemoteThread` a versatile tool in advanced adversary toolkits.

## 🛡️ Detection Opportunities

### 🔸 Behavioral Indicators
Detecting abuse of `CreateRemoteThread` requires monitoring for anomalous behavior involving remote process thread creation, especially when paired with memory allocation and writing APIs. Alerts should focus on processes that open handles to unrelated or high-privilege processes, allocate executable memory remotely, and then spawn threads at those locations. Attention to thread creation in suspended or uncommon target processes can also help surface stealthier techniques. While `CreateRemoteThread` itself is a legitimate API, its use in conjunction with suspicious process and memory manipulation patterns is a strong indicator of code injection or remote execution activity.

#### 1. Classic Process Injection
Attackers allocate memory in a remote process, write shellcode or a DLL path, then use `CreateRemoteThread` to execute. This straightforward method remains a staple in many malware families.

- `OpenProcess`
- `VirtualAllocEx`
- `WriteProcessMemory`
- `CreateRemoteThread`
- `CloseHandle`

#### 2. Reflective DLL Injection
Instead of relying on the Windows loader, attackers inject reflective DLLs directly into process memory and use `CreateRemoteThread` to trigger their execution.

- `OpenProcess`
- `VirtualAllocEx`
- `WriteProcessMemory`
- `CreateRemoteThread`
- `NtQueryInformationProcess`
- `CloseHandle`

#### 3. Suspended Process Payload Execution
Malicious actors create or target suspended processes to stage payloads quietly before using `CreateRemoteThread` (or resuming threads) to execute the code.

- `CreateProcess` (with `CREATE_SUSPENDED`)
- `VirtualAllocEx`
- `WriteProcessMemory`
- `CreateRemoteThread`
- `ResumeThread`

#### 4. Thread Hijacking and APC Injection
More stealthy approaches hijack or queue Asynchronous Procedure Calls (APCs) on existing threads, sometimes combined with `CreateRemoteThread` for follow-up execution.

- `OpenThread`
- `QueueUserAPC`
- `NtQueueApcThread`
- `SuspendThread`
- `ResumeThread`
- `CreateRemoteThread`
- `GetThreadContext`
- `SetThreadContext`

#### 5. Fileless / In-Memory Payload Execution
Payloads staged entirely in memory are triggered via remote threads without ever touching the disk, complicating detection.

- `OpenProcess`
- `VirtualAllocEx`
- `WriteProcessMemory`
- `CreateRemoteThread`

#### 6. DLL Hollowing / Process Replacement
Attackers unmap legitimate sections of a process, replace them with malicious code, then use `CreateRemoteThread` to start execution.

- `OpenProcess`
- `NtUnmapViewOfSection`
- `VirtualAllocEx`
- `WriteProcessMemory`
- `CreateRemoteThread`
- `ResumeThread`

#### 7. Variant: Handle Duplication
In some cases, attackers use `DuplicateHandle` to access threads or processes that would otherwise be restricted, duplicating handles from one process into another. This allows code injection or remote thread creation without invoking `OpenProcess` directly, helping evade detection mechanisms that monitor for process handle acquisition. Importantly, handle duplication can be combined with any of the injection techniques described above, enhancing stealth and flexibility.

- `OpenProcess` or `OpenThread`
- `DuplicateHandle`
- `VirtualAllocEx`
- `WriteProcessMemory`
- `CreateRemoteThread`

## 🦠 Malware & Threat Actors Documented Abusing CreateRemoteThread Patching

Below is a curated list of malware families, threat actors, and offensive tools known to abuse or patch `CreateRemoteThread` for defense evasion.  

For the latest technical write-ups, search for the malware or tool name together with "CreateRemoteThread" or "ETW evasion or patch" on reputable security blogs, threat intelligence portals, or simply google. (Direct links are not included to reduce maintenance.)

### **Ransomware**
 - BlackBasta
 - BlackMatter
 - FiveHands
 - Ryuk

### **Commodity Loaders & RATs**
 - DarkVison RAT
 - Emotet
 - HijackLoader
 - PNGPlug
 - PureCrypter
 - ResolverRAT

 ### **APT & Threat Actor Toolkits**
 - APT10
 - APT28 (Fancy Bear / Sofacy)
 - APT29 (Cozy Bear)
 - APT34 (OilRig)
 - Lazarus

### **Red Team & Open Source Tools**
 - Cobalt Strike
 - Metasploit
 - Mimikatz
 - Process Hacker

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `CreateRemoteThread` for stealth and evasion.

## 🧵 `CreateRemoteThread` and Friends
While `CreateRemoteThread` is one of the more direct and well-known APIs for remote code execution, it’s far from the only option. Adversaries often swap it out for alternatives like `NtCreateThreadEx`, `RtlCreateUserThread`, or `QueueUserAPC`, each offering different trade-offs in terms of stealth and reliability. Other approaches skip thread creation entirely by hijacking existing execution contexts with `SetThreadContext` or using section mapping and shared memory with `NtMapViewOfSection`. These substitutions are typically made to avoid detection rules that rely on spotting `CreateRemoteThread` specifically, while still achieving the same goal: executing malicious code in the context of a remote process.



## 📚 Resources 
* Microsoft Docs: [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)
* MITRE: [Process Injection](https://attack.mitre.org/techniques/T1055/)
* [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas) (More like this)

> **Know of more?**  
> Open a PR or issue to help keep this list up to date!
