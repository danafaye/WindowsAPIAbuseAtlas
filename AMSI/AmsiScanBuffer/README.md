# 🛡️ AmsiScanBuffer: Scan or Sneak 

## 🚀 Executive Summary
The frontline checkpoint, `AmsiScanBuffer`, is where in-memory scripts, macros, and dynamic code hit the defender’s radar. It’s the critical handoff from interpreters to antivirus engines, making it a prime battleground for attackers aiming to stay hidden. While designed to catch threats before they execute, it’s also a favored target for evasive malware and red teams who routinely find ways to disable, bypass, or deceive it. Understanding this API is key for defenders hunting stealthy, fileless, or living-off-the-land attacks that thrive in memory.

## 🔍 What is AmsiScanBuffer?
`AmsiScanBuffer` is how script hosts and interpreters (like PowerShell, WSH, and Office VBA) send raw content (scripts, macros, bytecode) to the system’s registered antimalware engine. It’s a runtime scan hook wired into the **Antimalware Scan Interface (AMSI)**. It’s a runtime scan hook wired into Windows: drop a payload in memory, and this API gives defenders one last shot to catch it before execution. Legitimate use is limited to environments that process untrusted input on the fly ... think interpreters and security tools.

AMSI itself is just the pipeline. Applications choose what to send and when. AmsiScanBuffer pushes the buffer to the AV/EDR engine via a COM interface (`IAntimalwareProvider`), and that engine decides if it’s clean or flagged. Windows only routes data through AMSI if the app is coded to do so.

By default, Microsoft wires these into AMSI:

 - **PowerShell**: all command blocks (unless bypassed)
 - **WSH (wscript/cscript)**: VBScript and JScript
 - **Office VBA**: macro source before execution
 - **MSHTA**: script inside HTML applications
 - **.NET**: dynamic assemblies via System.Reflection.Emit (newer versions)

Third-party apps can use AMSI, but most don’t unless they’re built for security. If the content doesn’t get sent, it doesn’t get scanned. Simple as that.

## 🚩 Why It Matters
`AmsiScanBuffer` is one of the last chances defenders have to catch malicious code before it runs. It’s where scripts, macros, and in-memory payloads get scanned (if they get scanned). Attackers know this, and most modern tooling includes ways to sidestep or disable it. If you're tracking threats that live in memory or abuse interpreters, understanding this API isn’t optional.

## 🧬 How Attackers Abuse It
Attackers don’t tiptoe around `AmsiScanBuffer`; they neutralize it. The most common move is to patch the function in memory; overwriting the start of `AmsiScanBuffer` with instructions like `mov eax, 0` to force a clean result. Expect to see `VirtualProtect`, `NtProtectVirtualMemory`, or `WriteProcessMemory` used to make the patch stick. Some malware unhooks AMSI entirely, severing the COM connection between the application and the antimalware provider. Look for tampering with `CoCreateInstance`, `IAntimalwareProvider`, or calls that alter registry keys under `HKLM\Software\Microsoft\AMSI`.

Others go upstream: they corrupt the scan buffer itself before it reaches AMSI; either by padding it with junk, XORing key strings, or chunking input. This often happens just before a call to `AmsiScanBuffer`, sometimes with a custom memory allocator or manipulation via `RtlMoveMemory` or `memcpy`. Some tools take out AMSI altogether by unloading or replacing amsi.dll, or calling `FreeLibrary`, or even hijacking DLL loading paths via `SetDllDirectory` or `LoadLibrary` to load a fake AMSI.

Red teams and real attackers don’t treat AMSI as a challenge. They treat it as a nuisance. One that’s easy to blind, bypass, or break if no one’s watching.

## 🛡️ Detection Opportunities
Here are some sample YARA rules to detect suspicious use of `AmsiScanBuffer`:

See [AmsiScanBuffer.yar](./AmsiScanBuffer.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
Monitoring these behaviors with telemetry tools, EDR hooks, or memory scanners can help spot when attackers try to blind or bypass AMSI, even if the raw payloads evade signature detection.

 - In-memory patching or hooking of `AmsiScanBuffer` (or related AMSI functions) to return fake “clean” results is common in PowerShell and script host processes.
 - Unusual API calls or memory writes targeting `ntdll!AmsiScanBuffer` or `amsi.dll` during runtime, especially in scripting or automation hosts.
 - Disabling or unregistering AMSI providers via registry changes or COM manipulation to block scanning entirely.
 - Presence of AMSI bypass patterns in scripts, such as Base64 encoded chunks designed to avoid scanning or runtime code that dynamically alters the scan buffer before submission.
 - Processes that normally call AMSI (PowerShell, WSH, Office) not making expected `AmsiScanBuffer` calls during suspicious script execution.
 - Unexpected loading of AMSI related DLLs (`amsi.dll`) into unusual processes that don’t typically use AMSI, which might indicate custom hooking or proxying.
 - Unusual sequences combining [VirtualAlloc](../../KERNEL32/VirtualAllocEx/), [WriteProcessMemory](../../KERNEL32/WriteProcessMemory/), and patching AMSI APIs within the same process or child processes.

## 🦠 Malware & Threat Actors Documented Abusing AmsiScanBuffer

### **Ransomware**
 - BlackCat/AlphV
 - Cuba
 - Ryuk

### **Commodity Loaders & RATs**
 - NonEuclid
 - SwaetRAT
 - XWorm

### **APT & Threat Actor Toolkits**
 - APT28
 - Punk Spider
 - Venomous Bear

### **Red Team & Open Source Tools**
 - Cobalt Strike
 - Metasploit
 - PowerChunker
 - Sharpblock

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `AmsiScanBuffer` for stealth and evasion.

## 🧵 `AmsiScanBuffer` and Friends
`AmsiScanBuffer` doesn’t stand alone in the memory scan game. You’ll often see it paired with `AmsiInitialize` and `AmsiOpenSession`, which set up the scanning context and maintain state. Attackers aiming to blind AMSI might target `AmsiScanString` for textual input or hook `AmsiScanBuffer` itself. Alongside these, APIs like `VirtualProtect` and `NtProtectVirtualMemory` often appear, used to modify memory protections.  These helping malware patch or unhook AMSI functions on the fly. In scripted environments, `CoCreateInstance` shows up as AMSI relies on COM interfaces to connect to registered antimalware providers. Together, these APIs form the core plumbing for AMSI’s runtime scanning, and the usual targets for evasion and tampering.

## 📚 Resources
- [Microsoft Docs: AmsiScanBuffer](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer)
- [MITRE T1562.001](https://attack.mitre.org/techniques/T1562/001/)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!