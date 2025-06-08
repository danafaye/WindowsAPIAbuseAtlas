# 🧪 EtwEventWrite Patching: Modern Threat Evasion & Detection

## 🚀 Executive Summary

**`EtwEventWrite` abuse** is a long-running and reliable tactic used by attackers to quietly turn off telemetry that defenders rely on. By patching or disabling this function, malware can hide from security tools that depend on Event Tracing for Windows (ETW). This trick has shown up in everything from basic commodity malware to advanced targeted attacks — because it works. In this entry, we break down how `EtwEventWrite` gets tampered with, why it matters, and what defenders can do about it.

---

## 🔍 What is EtwEventWrite?

**`EtwEventWrite` abuse** works because it strikes at the heart of how Windows tracks what’s happening under the hood. This API writes ETW (Event Tracing for Windows) events—fast, low-overhead logs that power everything from system diagnostics to security detections. EDRs and SIEMs lean on ETW to catch signs of process injection, module loads, and other suspicious behavior. When attackers patch `EtwEventWrite` in-memory, they can quietly kill that signal, leaving defenders in the dark.

---

## 🚩 Why It Matters in 2025

- **ETW patching is now mainstream:** Used by ransomware, loaders, APTs, and red teams.
- **Disrupts visibility for some security tools:** While many security tools use multiple telemetry sources, some still rely on ETW for key detections. Patching `EtwEventWrite` can reduce their visibility or break specific detections.
- **Rapidly evolving:** New obfuscation and patching techniques appear regularly.

---

## 🧬 How Attackers Abuse It

Malware or loaders locate `EtwEventWrite` in `ntdll.dll` and overwrite its prologue with instructions like `ret` or `xor rax, rax; ret`, effectively disabling event logging.

```asm
.text:00007FFEA1B61270 48 33 C0             xor     rax, rax
.text:00007FFEA1B61273 C3                   retn
```

## 🧵 Sample behavior

* Touches `ntdll.dll` memory in-process.
* Writes to `.text` section.
* Occurs early in malware execution (loader stage).

## 🛡️ Detection opportunities

### 🔹 YARA

Here are some sample YARA rules to detect EtwEventWrite patching: 

see [EtwEventWrite.yar](./EtwEventWrite.yar).

### 🔸 Behavioral Indicators

* Write access to `ntdll.dll` in-process.
* Calls to `VirtualProtect` on `ntdll.dll`.
* Usage of `GetProcAddress` with `EtwEventWrite`.

---

## 🦠 Malware & Threat Actors Documented Abusing EtwEventWrite Patching

Below is a curated list of malware families, threat actors, and offensive tools known to abuse or patch `EtwEventWrite` for defense evasion.  

For the latest technical write-ups, search for the malware or tool name together with "EtwEventWrite" or "ETW evasion or patch" on reputable security blogs, threat intelligence portals, or Malpedia. (Direct links are not included to reduce maintenance.)

### **Ransomware**
- LockBit
- Conti
- BlackCat/ALPHV
- Hive
- BlackMatter
- REvil/Sodinokibi
- Ragnar Locker
- DarkSide
- AvosLocker

### **Commodity Loaders & RATs**
- Cobalt Strike
- Brute Ratel C4
- Sliver
- Remcos RAT
- Metasploit

### **APT & Threat Actor Toolkits**
- Turla
- FIN7 (Carbanak)
- APT41
- Wizard Spider (TrickBot/Conti)

### **Red Team & Open Source Tools**
- Donut
- ScareCrow
- Invoke-ReflectivePEInjection
- SharpSploit
- Covenant

---

## 📚 Resources 

* Microsoft Docs: [EtwEventWrite](https://learn.microsoft.com/en-us/windows/win32/devnotes/etweventwrite)
* Geoff Chappel: [EtwEventWrite](https://www.geoffchappell.com/studies/windows/win32/ntdll/api/etw/evntapi/write.htm)

---

> **Know of more?**  
> Open a PR or issue to help keep this list up to date!
