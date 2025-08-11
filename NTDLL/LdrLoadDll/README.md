# 🧠 LdrLoadDll: Memory Loader

## 🚀 Executive Summary
`LdrLoadDll` is a lower level, undocumented function from `ntdll.dll` that loads a DLL into the virtual address space of the calling process. It operates beneath LoadLibrary* in the Windows loader stack, bypassing higher level Win32 API checks and instrumentation. While legitimate software might invoke it for specialized loading needs, attackers prize it for its stealth, sidestepping common API monitoring points and making dynamic library loading harder to detect.

## 🔍 What is LdrLoadDll?
`LdrLoadDll` is part of the Windows Loader routines inside ntdll.dll, typically invoked internally by functions like `LoadLibrary` and `LoadLibraryEx`. It accepts parameters for the search path, flags, DLL name, and a handle pointer to the loaded module. Being undocumented and residing at the Native API layer, it interacts directly with the loader’s internal data structures, bypassing some user-mode API wrappers and making it attractive for stealthy code execution.

## 🚩 Why It Matters
Because `LdrLoadDll` lives one layer deeper than the more familiar DLL loading APIs, monitoring solutions that only hook or patch `LoadLibrary*` calls may completely miss its usage. Attackers use it to, load malicious payloads without touching monitored API entry points; evade user-mode API hooks set by EDR products, and maintain stealth while still leveraging legitimate Windows loader functionality.

## 🧬 How Attackers Abuse It
Malicious operators call `LdrLoadDll` directly from injected shellcode or stagers to:

 - Load encrypted or fileless DLLs from memory.
 - Load DLLs from unusual paths (network shares, ADS, temp folders).
 - Bypass `AppInit_DLLs` or standard DLL search order monitoring.
 - Avoid triggering detection rules aimed at `LoadLibrary*`.

This can appear in post-exploitation toolkits, reflective loaders, and custom malware where stealth is more important than API stability.

## 🛡️ Detection Opportunities
 - Monitor `ETW` events from the Microsoft Windows Kernel Image provider for image load events and correlate them with processes that rarely load DLLs dynamically.
 - Hook or instrument `ntdll!LdrLoadDll` in EDR products to catch direct invocations.
 - Look for DLL loads from suspicious locations or with mismatched digital signatures.
 - Detect anomalous DLL load sequences that bypass normal initialization chains.

Here are some sample YARA rules to detect suspicious use of `LdrLoadDll`:

See [LdrLoadDll.yar](./LdrLoadDll.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - DLLs loaded from temp, AppData, or network paths via `LdrLoadDll`.
 - `LdrLoadDll` calls in processes not typically associated with custom DLL loading (like `winword.exe`, `excel.exe`).
 - DLL load events without preceding `LoadLibrary` calls in API call traces.
 - Execution of unsigned DLLs from memory without on disk presence.

## 🦠 Malware & Threat Actors Documented Abusing LdrLoadDll

### **Ransomware**
 - BlackCat
 - REvil
 - LockBit

### **Commodity Loaders & RATs**
 - Emotet
 - Formbook
 - Ursnif (Gozi)

### **APT & Threat Actor Toolkits**
 - APT32
 - APT41
 - Equation Group

### **Red Team & Open Source Tools**
 - Cobalt Strike
 - Metasploit
 - MimiKatz

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `LdrLoadDll`.

## 🧵 `LdrLoadDll` and Friends
`LdrLoadDll` often appears alongside or in place of several related APIs that serve similar purposes in module management and dynamic loading. At the higher level, `LoadLibraryA/W` are the more commonly used Win32 wrappers that eventually invoke `LdrLoadDll` under the hood, making them the “public” face of the same functionality. Once a DLL is loaded, `LdrGetProcedureAddress` is frequently called to resolve exported function addresses, enabling the loaded module’s code to be executed. When it’s time to remove a module, `LdrUnloadDll` handles cleanup and unloading. In some custom loader implementations, `NtMapViewOfSection` is used as an alternative to `LdrLoadDll`, particularly when loading DLLs as memory mapped sections rather than through the standard loader path.

## 📚 Resources
- [NTAPI Undocumented Functions Docs: LdrLoadDll](http://undocumented.ntinternals.net/index.html?page=UserMode/Undocumented+Functions/Executable+Images/LdrLoadDll.html)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!