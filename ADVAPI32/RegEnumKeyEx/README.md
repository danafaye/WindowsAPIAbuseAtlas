# 🔑 RegEnumKeyEx

## 🚀 Executive Summary
`RegEnumKeyEx` is one of those registry functions that quietly does a lot of heavy lifting. It lets a program list out all the subkeys under a given registry key. That’s super useful for normal software doing config checks… but it’s also a goldmine for attackers who want to figure out what’s installed, what defenses are running, and how they should adjust their next move.

## 🔍 What is RegEnumKeyEx?
Think of `RegEnumKeyEx` as a tour guide for the registry. You point it at a key, and it walks you through each subkey one at a time, giving you the names and some extra details. It’s part of `advapi32.dll`, and usually gets paired up with other registry APIs like `RegOpenKeyEx` to open the door before the tour begins.

## 🚩 Why It Matters
The Windows registry is like a blueprint of the system. It tells you what’s installed, how the system is configured, and even what security products are keeping watch. Attackers love using `RegEnumKeyEx` because it helps them adapt to whatever environment they’ve landed in. They can see if they’re inside a sandbox, check what antivirus is running, or just take inventory before deciding what to do next.

## 🧬 How Attackers Abuse It
Attackers lean on `RegEnumKeyEx` any time they want to take the pulse of a system without tipping their hand. Think of it like peeking through filing cabinets rather than smashing a window. It’s quiet, subtle, and usually blends in with normal behavior.

One of the classic moves is poking around in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`. That hive is basically a cheat sheet for what software is installed, from office suites to security tools. If malware sees entries for EDR or sandbox software, it might decide to bail out, stay dormant, or switch tactics. If it sees high value apps like database clients or backup software, that could signal the machine is worth extra attention.

Another favorite is `HKLM\SYSTEM\CurrentControlSet\Services`. By enumerating the services and drivers listed here, attackers can map out the security posture of the system and even identify juicy targets for privilege escalation. Some malware uses this info to disable services outright; others just note what’s running so they can dodge it.

Security related registry keys are an even bigger draw. Many antivirus and endpoint tools leave behind footprints in the registry that point to their configs, signatures, or status. By enumerating these, malware can figure out which defenses are active and adapt its payload accordingly. For example, ransomware operators often check for certain AVs and then deploy a custom bypass routine.

It’s not just reconnaissance, either. `RegEnumKeyEx` can be part of a decision tree that guides the malware’s entire execution flow. If it finds nothing interesting, it may behave one way. If it spots defenses, it behaves another. And if it sees signs of a sandbox or analysis VM like odd driver keys or missing software; it may just exit to avoid getting caught.

So while `RegEnumKeyEx` doesn’t directly “break” anything, it’s often a critical step in shaping how an attack unfolds. It’s the map-reading stage before the real journey begins.

## 🛡️ Detection Opportunities
By itself, `RegEnumKeyEx` isn’t inherently bad. Plenty of everyday apps use it. The trick is to watch the context. If an unsigned binary you’ve never seen before starts enumerating uninstall keys or digging into AV registry entries, that should raise eyebrows. Same if you see a process hammering the registry with tons of enumeration calls back to back. Logging tools like Sysmon or ETW registry providers can give you the visibility you need to catch that kind of behavior. 

Here are some sample YARA rules to detect suspicious use of `RegEnumKeyEx`:

See [RegEnumKeyEx.yar](./RegEnumKeyEx.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - Registry key enumeration targeting software uninstall keys
 - Enumeration of security product registry keys (AV/EDR, firewall settings)
 - Enumeration immediately followed by persistence related modifications
 - High frequency or large volume registry enumeration from a single process

## 🦠 Malware & Threat Actors Documented Abusing RegEnumKeyEx

### **Ransomware**
 - Conti
 - Ryuk

### **Commodity Loaders & RATs**
 - AyncRAT
 - Emotet
 - njRAT

### **APT & Threat Actor Toolkits**
 - APT32
 - APT41

### **Red Team & Open Source Tools**
 - Cobalt Strike
 - Metasploit

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `RegEnumKeyEx`.

## 🧵 `RegEnumKeyEx` and Friends
`RegEnumKeyEx` doesn’t usually work alone. It teams up with other registry APIs to make the whole picture useful. Attackers often start with `RegOpenKeyEx` to unlock a handle, then use `RegEnumKeyEx` to walk through subkeys, followed by `RegEnumValue` or `RegQueryValueEx` to dig into the actual data, like product names, install paths, or AV settings. In some cases, after scouting out autostart or service keys, malware pivots into `RegSetValueEx` or `RegCreateKeyEx` to plant persistence. That makes `RegEnumKeyEx` the scout of the group mapping the terrain and pointing attackers toward where to dig deeper or where to write new entries while its friends handle the heavy lifting of data extraction and persistence.

## 📚 Resources
- [Microsoft Docs: RegEnumKeyEx](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumkeyexa)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!