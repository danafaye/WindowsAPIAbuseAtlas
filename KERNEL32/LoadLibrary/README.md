# 🛠️ LoadLibrary

## 🚀 Executive Summary
If Windows APIs had celebrities, `LoadLibrary` would be on the A list. It’s one of the most well known and widely used functions in Windows, and for good reason: it loads a DLL into the calling process’s memory space. Every day, countless legitimate applications use it. But here’s the kicker ... attackers love it too. By hijacking the way DLLs are loaded, or by forcing malicious ones into memory, adversaries turn this otherwise boring API into a powerful tool for persistence, code execution, and stealth.

## 🔍 What is LoadLibrary?
At its core, `LoadLibrary` is an API in kernel32.dll that takes the path to a DLL, loads it into the process’s address space, and returns a handle to it. Once loaded, the process can call functions exported by that DLL. It’s part of the everyday mechanics of how Windows software runs; pretty much every program that relies on DLLs leans on LoadLibrary.

For developers, this is just “how Windows works.” But from a security perspective, this mechanism becomes a pressure point attackers can exploit.

## 🚩 Why It Matters
Because DLLs are flexible, modular, and everywhere, `LoadLibrary` sits at a junction of normal and malicious behavior. A benign app might load a graphics library, while malware might load a custom DLL packed with shellcode.

Attackers use LoadLibrary to:

 - Drop and load their own DLLs.
 - Hijack DLL search order to make Windows “accidentally” load a malicious DLL.
 - Inject DLLs into other processes (in combo with `WriteProcessMemory` and `CreateRemoteThread`).
 - Dynamically resolve and run payloads without leaving behind traditional indicators.

Basically, `LoadLibrary` lets adversaries bend Windows’ own loading system to their will.

## 🧬 How Attackers Abuse It
Think of `LoadLibrary` as the front door to Windows’ DLL system. Malware authors know if they can convince a process to open the door to their DLL, they win.

Classic abuses include DLL search order hijacking, where the system grabs a DLL from the wrong folder because it looks closer than the legit one. Another common trick is using `LoadLibrary` during process injection: write a malicious DLL into memory, then spin up a thread that calls `LoadLibrary` on it. And in some commodity malware families, `LoadLibrary` is the workhorse for loading encrypted payloads at runtime.

One of the stealthier tricks is pairing `LoadLibrary` with `GetProcAddress`. By first calling `LoadLibrary`, malware can dynamically load a library into memory, and then instead of importing functions the “normal” way (which leaves clear traces in the import table), it uses `GetProcAddress` to look up the address of the function it wants. That way, no suspicious APIs are visible in the static imports of the binary. It all happens dynamically at runtime. To defenders analyzing binaries, this can make a malicious sample look much less capable than it really is.

Because `LoadLibrary` so common in legit apps, adversaries get cover for the “noise” that makes it hard for defenders to separate normal DLL loads from shady ones.

## 🛡️ Detection Opportunities
Detecting malicious `LoadLibrary` use is tricky because the API is ubiquitous. The key is to focus on context and anomalies.

Here are some sample YARA rules to detect suspicious use of `LoadLibrary`:

See [LoadLibrary.yar](./LoadLibrary.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - A process loading DLLs from unusual directories (temp folders, user profile paths, or web-downloaded locations).
 - Unexpected DLL loads by processes that don’t normally use them (like Office suddenly loading wininet.dll).
 - A surge in DLL load activity right before or after process injection.
 - DLL loads where the file is unsigned, recently dropped, or mismatched with its expected hash.
 - Suspicious API call chains: `WriteProcessMemory` → `CreateRemoteThread` → `LoadLibrary`.

## 🦠 Malware & Threat Actors Documented Abusing LoadLibrary
`LoadLibrary` is so ubiquitous it seems funny to fill this section out, but here are some examples anyway.

### **Ransomware**
- Charon
- LockBit
- SafePlay

### **Commodity Loaders & RATs**
 - AsyncRAT
 - Bumblebee
 - Kronos

### **APT & Threat Actor Toolkits**
 - APT29
 - APT32
 - APT41

### **Red Team & Open Source Tools**
 - Cobalt Strike 
 - Metasploit
 - Sliver

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `LoadLibrary`.

## 🧵 `LoadLibrary` and Friends
`LoadLibrary` practically never works alone. Its extended family includes `LoadLibraryEx` (adds flags for more granular control), `GetProcAddress` (to call specific functions in a loaded DLL), and `FreeLibrary` (to unload). Together, they form the foundation of dynamic linking in Windows. When you see one, you’ll often see the others.

## 📚 Resources
- [Microsoft Docs: LoadLibrary](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!