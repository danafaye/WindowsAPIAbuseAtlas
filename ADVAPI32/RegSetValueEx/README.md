# RegSetValueEx 🧱🪄

## 🚀 Executive Summary  
`RegSetValueEx` writes a value to a specified registry key. It’s everywhere, used by installers, sysadmin tools, legit software, but also abused by attackers to persist, stage payloads, or manipulate system behavior. The trick isn’t catching the API call, it’s catching it with the **right context**: which key, from what process, doing what kind of damage.

## 🚩 Why It Matters  
This API gives malware a foothold. Whether it’s setting a `Run` key to relaunch on reboot, stashing shellcode in an obscure registry path, or hijacking execution flow via COM/ActiveX trickery, `RegSetValueEx` enables all kinds of stealthy abuse. Defenders often overlook it because it's so noisy, but targeted analysis of value names, types, and ancestry makes it gold for persistence and misdirection detection.

## 🧬 How Attackers Abuse It  

- **Persistence**: Drop entries in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` to execute malware on login.
- **Payload staging**: Store encrypted shellcode or full payloads in obscure registry paths.
- **LOLBAS hijacking**: Modify keys like `Image File Execution Options` or `Debugger` to hijack built-in tool execution.
- **COM Hijacking**: Write fake class registration data under `HKCU\Software\Classes\CLSID` to hijack execution.
- **Masquerading / evasion**: Modify telemetry tool config or suppress crash reporting by altering keys.

## 🧩 Common Abuse Paths

### 🔐 Persistence via Run Key  
1. `RegOpenKeyEx` or `RegCreateKeyEx`  
2. `RegSetValueEx` ,  write path to malware in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`  

### 📦 Payload in Registry  
1. `RegCreateKeyEx` ,  create staging path (e.g., `HKCU\Software\BadGuy\Config`)  
2. `RegSetValueEx` ,  write shellcode or encoded payload into string or binary value  

### 🪞 COM Hijacking  
1. `RegOpenKeyEx` ,  open CLSID path under `HKCU\Software\Classes`  
2. `RegSetValueEx` ,  write hijacked `InProcServer32` or `ShellFolder` path  

### 🧪 LOLBAS & Debugger Abuse  
1. `RegOpenKeyEx` ,  open `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe`  
2. `RegSetValueEx` ,  set `Debugger` value to dropper or payload  

## 🛡️ Detection Opportunities  

### 🔹 YARA  
Here are some sample YARA rules to detect suspicious use of `RegSetValueEx`:

See [RegSetValueEx.yar](./RegSetValueEx.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🔸 Behavioral Indicators  

Look for `RegSetValueEx` activity coming from processes that aren’t installers or admin tools, especially when it shows up in things like `explorer.exe`, `wscript.exe`, or `svchost.exe`, which shouldn’t normally be writing to the registry. 

Pay close attention to writes targeting keys like `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, or anything under `HKCU\Software\Classes\CLSID\*`. These are common persistence or hijack points. 

Suspicious values that decode to PE files or shellcode (base64, hex blobs, etc.) are another strong indicator. Registry writes followed closely by execution APIs, `CreateProcess`, `ShellExecute`, `NtCreateThreadEx`, can signal staging or payload launch. 

Context matters here, so pair registry activity with process ancestry, execution flow, and endpoint telemetry to separate actual abuse from background noise.

## 🦠 Malware & Threat Actors Documented Abusing RegSetValueEx

### Ransomware  
- LockBit  
- BlackCat  
- Dharma

### Commodity Loaders & RATs  
- Agent Tesla  
- FormBook  
- AsyncRAT

### APT & Threat Actor Toolkits  
- APT33 (using COM hijacking)  
- FIN7  
- Turla

### Red Team & Open Source Tools  
- Cobalt Strike (via stagers)  
- Empire  
- SharpPersist  
- PowerSploit

> 📌 Note: This API is used *everywhere*. Context is everything. Not every `RegSetValueEx` is malicious, but some are incredibly telling.

## 🧵 `RegSetValueEx` and Friends  

While `RegCreateKeyEx` is the go-to API for creating registry keys, it’s definitely not the only game in town. There are a handful of very similar functions, like `RegCreateKey`, `RegCreateKeyW`, and `RegCreateKeyExW`, that offer nearly the same capabilities but differ slightly in Unicode support or parameters. Beneath all these Win32 APIs lie Native API functions like `NtCreateKey` and `ZwCreateKey` that provide the same core functionality at a lower level. Malware sometimes calls these directly to bypass user-mode hooks and evade detection. Knowing this family of related functions is crucial because attackers swap between them depending on environment or technique, making registry abuse a moving target for defenders.

## 📚 Resources  
- [Microsoft Docs – RegSetValueExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexw)  
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)


> 🛠 Know of more creative abuses?  
> Open a PR or issue and help grow the Atlas.
