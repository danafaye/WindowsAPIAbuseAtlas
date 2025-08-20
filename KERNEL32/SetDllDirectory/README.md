# 🛠️ SetDllDirectory

## 🚀 Executive Summary
`SetDllDirectory` lets a program modify the search path Windows uses to locate DLLs. This is super handy for developers who want to load libraries from custom locations, but it also opens the door to DLL hijacking, sideloading, and persistence tricks. Attackers love APIs like this because it lets them redirect where Windows looks for code, swapping out trusted libraries for their own malicious versions.

## 🔍 What is SetDllDirectory?
Normally, when an application loads a DLL, Windows checks a standard list of familiar directories ... things like the application’s folder, System32, and the PATH environment variable. The `SetDllDirectory` function changes that order by inserting or removing directories. This means the application will look somewhere else first (or ignore some places entirely).

For developers, it solves dependency headaches. For attackers, it’s a stealthy way to influence how and where code gets loaded.

## 🚩 Why It Matters
Because DLL loading happens all the time in Windows, messing with search paths can have wide reaching effects. If an attacker can control what directory a process trusts first, they can sneak in a malicious DLL that gets executed instead of the real one.

It’s one of those APIs that isn’t flashy on its own, but when combined with filesystem tricks, persistence, or privilege escalation, it becomes a powerful piece of the puzzle.

## 🧬 How Attackers Abuse It
Attackers don’t call `SetDllDirectory` for fun. They’ll:

 - Redirect an application to load a malicious DLL from a folder they control.
 - Drop a fake DLL in a directory that is now “trusted” because of a modified search path.
 - Use it as part of a sideloading chain where a legitimate binary imports a DLL, but attackers decide where Windows looks first.

In short, it’s about bending the rules of DLL resolution in their favor.

## 🛡️ Detection Opportunities
Monitoring API usage is one way to catch suspicious `SetDllDirectory` calls, but context matters. Some apps genuinely use this for compatibility. What stands out is when it’s called by processes that don’t usually load from custom directories, or when the new path points to odd places like temp folders, user profile directories, or removable drives.

Here are some sample YARA rules to detect suspicious use of `SetDllDirectory`:

See [SetDllDirectory.yar](./SetDllDirectory.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
- A process calling SetDllDirectory followed by LoadLibrary from non-standard paths.
 - DLL loads from writable directories (Downloads, Temp, Desktop).
 - Persistence mechanisms where registry run keys or scheduled tasks launch binaries that tweak DLL search paths.

## 🦠 Malware & Threat Actors Documented Abusing SetDllDirectory

### **Ransomware**
- CatB
- LockBit
- StopCrypt

### **Commodity Loaders & RATs**
- FormBook
- NetWire RAT
- TrickBot

### **APT & Threat Actor Toolkits**
- APT41
- Louse
- ToddyCat 

### **Red Team & Open Source Tools**
- Cobalt Strike
- Probably others?  Let me know.

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `SetDllDirectory`.

## 🧵 `SetDllDirectory` and Friends
SetDllDirectory doesn’t act alone. It often pairs with:

 - `LoadLibrary` or `LoadLibraryEx`: To actually pull in the targeted DLLs.
 - `AddDllDirectory` & `RemoveDllDirectory`: More modern, granular APIs for managing DLL search paths.
 - `SetSearchPathMode`: Lets apps control how Windows searches for DLLs more broadly.

## 📚 Resources
- [Microsoft Docs: SetDllDirectory](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setdlldirectorya)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!