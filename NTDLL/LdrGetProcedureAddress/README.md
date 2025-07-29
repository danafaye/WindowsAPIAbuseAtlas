# 🎯 LdrGetProcedureAddress: Resolver beneath Win32

## 🚀 Executive Summary
`LdrGetProcedureAddress` is a native export from ntdll.dll used to resolve function addresses from loaded modules without relying on higher level Win32 APIs like `GetProcAddress`. It’s quiet, stripped down, and ideal for custom loaders, shellcode, and low noise execution environments. Long present in Windows internals, it’s a favorite among malware and red team tools looking to sidestep userland hooks and evade detection. If it’s in play, something wants precision and doesn’t want to be seen.

## 🔍 What is LdrGetProcedureAddress?
An internal routine exported by `ntdll.dll`, `LdrGetProcedureAddress` resolves function addresses from a loaded module using a name or ordinal. It bypasses the higher layers of the Win32 API, interacting directly with the loader’s internal structures. Not officially documented by Microsoft, but long present and stable across versions. It shows up in environments where kernel32.dll isn’t available, wanted, or initialized yet, bootstrapping phases, minimal runtimes, or tight control flows. It’s foundational, sparse, and built for systems operating closer to the native layer than most user mode code ever does.

## 🚩 Why It Matters
`LdrGetProcedureAddress` sits just beneath the surface of what most tools and analysts inspect. It’s part of the machinery that makes higher level APIs work, but it doesn’t announce itself. Knowing it exists, and what layer it lives in, helps untangle behaviors that skip the usual paths. It’s a reminder that not all function calls come wrapped in Win32, and not all code plays by the same rules.

## 🧬 How Attackers Abuse It
`LdrGetProcedureAddress` shows up when stealth is the goal and noise is the problem. Red team tools and malware lean on it to resolve imports without touching kernel32's `GetProcAddress`, dodging hooks, EDR symbols, and behavioral signatures that watch for common API usage. It's often paired with `LdrLoadDll` to build custom loaders that never call a single high level API. By walking the native layer, payloads can bootstrap execution, resolve only what they need, and leave behind fewer footprints in memory, telemetry, and logs.

## 🛡️ Detection Opportunities
Here are some sample YARA rules to detect suspicious use of `LdrGetProcedureAddress`:

See [LdrGetProcedureAddress.yar](./LdrGetProcedureAddress.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
Spotting `LdrGetProcedureAddress` in the wild takes a step back from the usual API call chains. It won’t show up in high level telemetry unless you're already logging ntdll exports, so memory inspection and behavioral correlation matter more. Look for patterns where `LdrLoadDll` is used to bring in modules manually, followed closely by `LdrGetProcedureAddress` resolving key APIs like `VirtualAlloc`, `CreateThread`, or `NtProtectVirtualMemory`. In packed or staged payloads, this often follows a custom loader stub and may appear obfuscated or indirect, watch for function hashes or encoded strings feeding into the API lookup logic.

From a reverse engineering angle, check for manual PEB traversal leading to base addresses passed to `LdrGetProcedureAddress`, often with ANSI or Unicode strings pointing to functions that match a known execution chain. The absence of a normal import table, coupled with a late stage resolver that touches ntdll directly, is a strong tell. If the binary avoids importing kernel32.dll entirely but still manages thread creation or memory operations, you’re almost certainly looking at this technique.

## 🦠 Malware & Threat Actors Documented Abusing LdrGetProcedureAddress
`LdrGetProcedureAddress` abuse isn’t new. This native function has quietly existed since the beginning of Windows dating back to Windows NT 3.1. Its low level nature means it’s less common in everyday software but a steady favorite among advanced tooling, custom loaders, and malware authors who want to fly under the radar. Over time, its use has steadily increased in sophisticated threats and red team frameworks as detection at higher API layers improved. It’s a staple for anyone operating beneath the typical Win32 surface.

### **Ransomware**
- DarkSide
- LockBit
- REvil (Sodinokibi)

### **Commodity Loaders & RATs**
- BumbleBee Loader
- Emotet
- QakBot (Qbot)

### **APT & Threat Actor Toolkits**
- APT29 (Cozy Bear) Toolset
- Turla (Snake) Framework
- Lazarus Group Loader Modules

### **Red Team & Open Source Tools**
- Cobalt Strike Beacon
- Metasploit Framework
- SharpSploit

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `LdrGetProcedureAddress`.

## 🧵 `LdrGetProcedureAddress` and Friends
`LdrGetProcedureAddress` isn’t the only way to resolve function addresses. The more familiar `GetProcAddress` lives higher up in `kernel32.dll`, wrapping similar logic with added safety and compatibility layers. There’s also `NtGetProcAddress` variants hidden deeper in ntdll or kernel components, sometimes used in kernel mode or specialized contexts. Together, these APIs form a hierarchy from native, low level resolution in ntdll to the polished, public facing interfaces in Win32 each serving similar purposes but designed for different trust and execution layers.

## 📚 Resources
- [undocumented.ntinternals.net: LdrGetProcedureAddress](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FLdrGetDllHandle.html)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!