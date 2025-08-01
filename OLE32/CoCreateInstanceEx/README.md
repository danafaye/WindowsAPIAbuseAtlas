# 🛠️ CoCreateInstanceEx

## 🚀 Executive Summary
`CoCreateInstanceEx` is a powerful Windows API used to create single uninitialized objects remotely. It’s commonly used in enterprise applications and Windows internals, but attackers also leverage it to instantiate COM classes in flexible and stealthy ways. Its support for remote activation and configurable security context allows abuse cases that bypass traditional process boundaries, avoid disk-based payloads, and cross trust levels. For defenders, understanding how this API is abused is key to detecting lateral movement, privilege escalation, and even sandbox evasion techniques.

## 🔍 What is CoCreateInstanceEx?
`CoCreateInstanceEx` is part of the Component Object Model (COM) infrastructure in Windows and is defined in `objbase.h`. It creates and initializes a COM object based on a specified CLSID and can return one or more interface pointers through the `MULTI_QI` array. This function is a more versatile alternative to [CoCreateInstance](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/OLE32/CoCreateInstance), as it supports instantiating objects both locally and remotely through DCOM using the `COSERVERINFO` structure.

Unlike [CoCreateInstance](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/OLE32/CoCreateInstance), which is limited to single-interface instantiation on the local system, `CoCreateInstanceEx` offers:
- The ability to request multiple interfaces in a single call.
- Support for creating the COM object on a remote machine (if DCOM is enabled).
- Fine-grained control over security context and marshaling behavior.

## 🚩 Why It Matters
While `CoCreateInstanceEx` is often used for legitimate automation or system integration, its extended capabilities make it an attractive option for attackers. The API allows for instantiation of powerful COM classes both locally and remotely often without spawning new processes or writing payloads to disk.

This flexibility makes it ideal for:
- **Instantiating LOLBAS-style COM objects** (for bypassing UAC).
- **Executing code or loading DLLs via COM callbacks**, potentially without leaving obvious forensic traces.
- **Lateral movement**, since attackers can instantiate classes on remote systems over DCOM.
- **Interface hijacking or privilege escalation**, by instantiating COM objects exposed by elevated processes or system services.


## 🧬 How Attackers Abuse It
Attackers abuse `CoCreateInstanceEx` to instantiate COM classes that lead to code execution or privilege escalation, often in a way that bypasses common detection methods. Examples include:

- **Remote activation** of objects on a target machine for lateral movement, bypassing traditional remote service creation methods.
- **Instantiation of known malicious COM CLSIDs**, such as those linked to UAC bypasses (`{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` for `ICMLuaUtil`).
- **Loading COM-based interfaces to sensitive services**, such as Task Scheduler, WMI, or Shell Windows, enabling attackers to manipulate system settings or execute payloads in trusted processes.
- **Evading sandboxes** that don’t properly support DCOM or interface marshaling by relying on out-of-process object activation.

## 🛡️ Detection Opportunities
While benign applications frequently use `CoCreateInstanceEx`, several heuristics can signal abuse:

- Unexpected CLSIDs (rare or undocumented) being passed to `CoCreateInstanceEx`.
- Remote object activation targeting systems outside typical administrative domains.
- Unusual use in processes like `wscript.exe`, `mshta.exe`, or `rundll32.exe`.
- Execution context mismatches (e.g., low-integrity process requesting high-integrity COM object).

Here are some sample YARA rules to detect suspicious use of `CoCreateInstanceEx`:

See [CoCreateInstanceEx.yar](./CoCreateInstanceEx.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
- Remote COM activation initiated by user-level processes.
- Registry reads to `HKCR\CLSID\{...}` followed by COM activation in short succession.
- DLL loads following interface marshaling or instantiation of known LOLBIN CLSIDs.
- `svchost.exe` or `explorer.exe` spawning unusual child processes shortly after COM instantiation.

## 🦠 Malware & Threat Actors Documented Abusing CoCreateInstanceEx

### **Ransomware**
- Conti
- LockBit

### **Commodity Loaders & RATs**
- Qakbot
- AgentTesla

### **APT & Threat Actor Toolkits**
- APT29
- APT33

### **Red Team & Open Source Tools**
- SharpCOM
- Invoke-DCOM
- GhostPack's Seatbelt

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `CoCreateInstanceEx`.

## 🧵 `CoCreateInstanceEx` and Friends
`CoCreateInstanceEx` often appears alongside other COM-related APIs that enable flexible object instantiation and control. `CoInitializeEx` is typically called first to initialize the COM library with a specific threading model. In some cases, attackers may opt for `CoGetClassObject` to retrieve a class factory before creating the object, giving them more direct control over the instantiation process. While [CoCreateInstance](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/OLE32/CoCreateInstance) is a simpler alternative limited to local object creation with a single interface, `CoCreateInstanceEx` enables more advanced use cases, including remote activation and multiple interface queries. For post-instantiation control, `CoSetProxyBlanket` is commonly used to set authentication and impersonation levels on the interface proxy — a crucial step for crossing privilege or network boundaries. Interfaces like `ICMLuaUtil`, `IShellWindows`, and `IWbemLocator` are often targeted through `CoCreateInstanceEx` to achieve UAC bypass, shell manipulation, or system enumeration.

## 📚 Resources
- [Microsoft Docs: CoCreateInstanceEx](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstanceex)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!
