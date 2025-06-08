# 🧪 EtwEventWrite Patching: Modern Threat Evasion & Detection

## 🚀 Executive Summary

**Event Tracing for Windows (ETW)** is a core telemetry mechanism leveraged by security products and defenders. In 2025, patching or disabling `EtwEventWrite` remains a *top-tier* evasion tactic for both commodity malware and advanced threat actors. This project provides actionable detection strategies, technical context, and curated resources to help blue teams, researchers, and red teamers stay ahead of evolving tradecraft.

---

## 🔍 What is EtwEventWrite?

`EtwEventWrite` is a Windows API responsible for writing ETW events. Attackers frequently patch this function in-memory to suppress telemetry, blinding EDRs and SIEMs to their activity.

---

## 🚩 Why It Matters in 2025

- **ETW patching is now mainstream:** Used by ransomware, loaders, APTs, and red teams.
- **Bypasses modern EDRs:** Many solutions still rely on ETW for behavioral detection.
- **Rapidly evolving:** New obfuscation and patching techniques appear regularly.

---

## 🧬 How Attackers Abuse It

Malware or loaders locate `EtwEventWrite` in `ntdll.dll` and overwrite its prologue with instructions like `ret` or `xor rax, rax; ret`, effectively disabling event logging.

```asm
.text:00007FFEA1B61270 48 33 C0              xor     rax, rax
.text:00007FFEA1B61273 C3                   retn
```

## 🧵 Sample behavior

* Touches `ntdll.dll` memory in-process.
* Writes to `.text` section.
* Occurs early in malware execution (loader stage).

## 🛡️ Detection opportunities

### 🔹 YARA (Memory Scan)

Here are some sample YARA rules to detect EtwEventWrite patching (including LockBit and other malware): see [EtwEventWrite.yar](./EtwEventWrite.yar).

### 🔸 Behavioral Indicators

* Write access to `ntdll.dll` in-process.
* Calls to `VirtualProtect` on `ntdll.dll`.
* Usage of `GetProcAddress` with `EtwEventWrite`.

---

## 🦠 Malware & Threat Actors Documented Abusing EtwEventWrite Patching

Below is a curated list of malware families, threat actors, and offensive tools known to abuse or patch `EtwEventWrite` for defense evasion.  

For the latest technical write-ups, search for the malware or tool name together with "EtwEventWrite patching" or "ETW evasion" on reputable security blogs, threat intelligence portals, or Malpedia. (Direct links are not included to reduce maintenance.)

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

> **Tip:** For up-to-date technical details, search for the malware or tool name plus "EtwEventWrite patching" on sites like Malpedia, MITRE ATT&CK, or leading vendor blogs.

---

## 📚 Resources 

* Microsoft Docs: [EtwEventWrite](https://learn.microsoft.com/en-us/windows/win32/devnotes/etweventwrite)
* Geoff Chappel: [EtwEventWrite](https://www.geoffchappell.com/studies/windows/win32/ntdll/api/etw/evntapi/write.htm)

---

> **Know of more?**  
> Open a PR or issue to help keep this list up to date!
