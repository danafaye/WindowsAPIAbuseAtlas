# 🛠️ AmsiScanString

## 🚀 Executive Summary
`AmsiScanString` is one of the crown jewels of Microsoft’s Antimalware Scan Interface (AMSI). It gives security tools a peek inside potentially dangerous strings. Think PowerShell commands, JavaScript snippets, or script content loaded at runtime. While defenders rely on it to flag malicious code before execution, attackers see it as a roadblock that needs to be bypassed, patched, or neutered. Understanding how AmsiScanString works, and how adversaries wriggle around it  is essential for both building detections and recognizing evasion tricks in the wild.

## 🔍 What is AmsiScanString?
`AmsiScanString` is a Windows API provided by AMSI that lets applications and services send strings of content (like scripts or commands) to an antimalware engine for inspection. It’s often invoked by script hosts like PowerShell or Windows Script Host whenever new code is being executed. In plain English: it’s the API that helps antivirus products catch malicious scripts in memory, before they run wild.

## 🚩 Why It Matters
The string level inspection that `AmsiScanString` enables is a huge defensive win. Without it, obfuscated PowerShell or memory script payloads would sail under the radar. But because it’s such a critical chokepoint, attackers spend significant energy figuring out how to disable it. If you see someone tampering with or bypassing AmsiScanString, it’s almost always an indicator of malicious intent.

## 🧬 How Attackers Abuse It
Attackers don’t typically call `AmsiScanString directly (unless they’re testing detections). Instead, their abuse comes in the form of trying to get around it. Classic tricks include:

 - Patching the function in memory so it always returns “clean.”
 - Overwriting the function pointer in amsi.dll, effectively breaking the scanning pipeline.
 - Unloading or disabling AMSI altogether, forcing Windows components to execute without scanning.
 - Encoding or chunking payloads so malicious strings slip through before AMSI has a chance to inspect them.

The irony is that the presence of `AmsiScanString` makes it a favorite target for attackers. What was meant as a shield often becomes the first thing they try to smash.

## 🛡️ Detection Opportunities
Defenders can hunt for suspicious modifications to AmsiScanString or the DLLs that house it. For example:

 - Monitoring memory patches to amsi.dll or inline hooks inside processes like PowerShell.
 - Flagging when AmsiScanString suddenly starts returning unexpected values (like constant “clean” results).
 - Looking for processes that load amsi.dll but immediately disable its exports.

Here are some sample YARA rules to detect suspicious use of `AmsiScanString`:

See [AmsiScanString.yar](./AmsiScanString.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - PowerShell or WSH processes loading amsi.dll and then exhibiting API patching behavior.
 - Scripts that load shellcode or encoded payloads after AMSI tampering.
 - Inline patch signatures (like mov eax, 0; ret) inside AmsiScanString.

## 🦠 Malware & Threat Actors Documented Abusing AmsiScanString

### **Ransomware**
- LockBit
- Play

### **Commodity Loaders & RATs**
- Agent Telsa
- BlotchyQuasar
- Remcos RAT

### **APT & Threat Actor Toolkits**
- APT28
- APT41
- Lazarus

### **Red Team & Open Source Tools**
 - Cobalt Strike
 - Metasploit

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `AmsiScanString`.

## 🧵 `AmsiScanString` and Friends
`AmsiScanString` is usually seen alongside its sibling APIs like [AmsiScanBuffer](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/AMSI/AmsiScanBuffer), which scan chunks of data instead of just strings. Attackers who go after one often try to neuter the whole AMSI pipeline, so defenders should widen their focus beyond a single function.

## 📚 Resources
- [Microsoft Docs: AmsiScanString](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanstring)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!