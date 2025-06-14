# 🧪 EtwEventWrite Patching

## 🚀 Executive Summary

**`EtwEventWrite` patching** is a long-running and reliable tactic used by attackers to quietly turn off telemetry that defenders rely on. By patching or disabling this function, malware can hide from security tools that depend on Event Tracing for Windows (ETW). This trick has shown up in everything from basic commodity malware to advanced targeted attacks — because it works. In this entry, we break down how `EtwEventWrite` gets tampered with, why it matters, and what defenders can do about it.

## 🔍 What is EtwEventWrite?

**`EtwEventWrite` patching** works because it strikes at the heart of how Windows tracks what’s happening under the hood. This API writes ETW (Event Tracing for Windows) events—fast, low-overhead logs that power everything from system diagnostics to security detections. EDRs and SIEMs lean on ETW to catch signs of process injection, module loads, and other suspicious behavior. When attackers patch `EtwEventWrite` in-memory, they can quietly kill that signal, leaving defenders in the dark.

## 🚩 Why It Matters

- **ETW patching is mainstream:** Used by ransomware, loaders, APTs, and red teams.
- **Disrupts visibility for some security tools:** While many security tools use multiple telemetry sources, some still rely on ETW for key detections. Patching `EtwEventWrite` can reduce their visibility or break specific detections.
- **Rapidly evolving:** New obfuscation and patching techniques appear regularly.

## 🧬 How Attackers Abuse It

Malware or loaders locate `EtwEventWrite` in `ntdll.dll` and overwrite its prologue with instructions like `ret` or `xor rax, rax; ret`, effectively disabling event logging.

> ```
> .text:00007FFEA1B61270 48 33 C0             xor     rax, rax
> .text:00007FFEA1B61273 C3                   retn
> ```

## 🧵 Sample Behavior

- Touches `ntdll.dll` memory in-process.
- Writes to `.text` section.
- Occurs early in malware execution (loader stage).

## 🛡️ Detection Opportunities

### 🔹 YARA

Here are some sample YARA rules to detect EtwEventWrite patching: 

See [EtwEventWrite.yar](./EtwEventWrite.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🔸 Behavioral Indicators

- Write access to `ntdll.dll` in-process.
- Calls to `VirtualProtect` on `ntdll.dll`.
- Usage of `GetProcAddress` with `EtwEventWrite`.

## 🦠 Malware & Threat Actors Documented Abusing EtwEventWrite Patching

Below is a curated list of malware families, threat actors, and offensive tools known to abuse or patch `EtwEventWrite` for defense evasion.  

For the latest technical write-ups, search for the malware or tool name together with "EtwEventWrite" or "ETW evasion or patch" on reputable security blogs, threat intelligence portals, or simply google. (Direct links are not included to reduce maintenance.)

### **Ransomware**
- BlackCat/ALPHV
- Hive/Mallox
- LockBit
- Pandora
- REvil/Sodinokibi

### **Commodity Loaders & RATs**
- Cobalt Strike
- Brute Ratel C4
- Sliver
- Remcos RAT
- Metasploit

### **APT & Threat Actor Toolkits**
- APT41
- FIN7 (Carbanak)
- Turla
- Wizard Spider (TrickBot/Conti)

### **Red Team & Open Source Tools**
- Donut
- ScareCrow
- Invoke-ReflectivePEInjection
- SharpSploit
- Covenant

## 🧵 `EtwEventWrite` and Friends

**`EtwEventWrite` abuse** is a long-running and reliable tactic used by attackers to quietly turn off telemetry that defenders rely on. But it's not the only ETW function worth watching. `EtwEventWrite` belongs to a small family of related functions—like `EtwEventWriteEx`, `EtwEventWriteFull`, `EtwEventWriteTransfer`, and `EtwEventWriteNoRegistration`—that all play slightly different roles in event logging.

These variants extend `EtwEventWrite` with features like activity correlation (`EtwEventWriteTransfer`), additional context (`EtwEventWriteEx`, `Full`), or even bypasses to the normal registration path (`EtwEventWriteNoRegistration`). While `EtwEventWrite` is the most frequently patched or hooked, attackers looking to sidestep detection may increasingly turn to these lesser-known siblings.

**If you're only monitoring or protecting `EtwEventWrite`, you're probably missing part of the picture.**

## 📚 Resources 

* Microsoft Docs: [EtwEventWrite](https://learn.microsoft.com/en-us/windows/win32/devnotes/etweventwrite)
* Geoff Chappel: [EtwEventWrite](https://www.geoffchappell.com/studies/windows/win32/ntdll/api/etw/evntapi/write.htm)

> **Know of more?**  
> Open a PR or issue to help keep this list up to date!
