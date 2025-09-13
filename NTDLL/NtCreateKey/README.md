# 🔑 NtCreateKey

## 🚀 Executive Summary
`NtCreateKey` allows creation of new registry keys within the Windows Registry. While often benign and used by legitimate applications for configuration storage, attackers can abuse this API to establish persistence, hide malicious configuration data, or manipulate system behavior by writing to sensitive registry paths. Its abuse is a common thread across malware families, loaders, and persistence toolkits.

## 🔍 What is NtCreateKey?
`NtCreateKey` is a low level Native API function that creates or opens a registry key object. It sits below Win32 functions such as `RegCreateKeyEx` and provides attackers finer control with fewer hooks or monitoring points by EDR solutions.

## 🚩 Why It Matters
The Windows Registry functions as the operating system’s central nervous system, storing both system wide and user specific configuration data. By creating keys in the registry, attackers can anchor themselves to a machine, ensuring that their malicious code launches automatically with system startup or user logon. They can also use the registry as a hidden storage medium, tucking away command and control information, payloads, or encryption keys in obscure or obfuscated registry paths. This makes `NtCreateKey` a vital tool for attackers aiming to survive reboots, stay undetected, and operate flexibly without leaving obvious artifacts.

## 🧬 How Attackers Abuse It
Malware authors and red teams alike exploit `NtCreateKey` to gain a foothold. A common technique involves creating persistence keys under Run or RunOnce, ensuring that malicious executables launch automatically. Others leverage it to stash encoded blobs or payloads within benign looking registry hives, avoiding the need for file based indicators of compromise. Some families have gone further, manipulating service related keys under `HKLM\SYSTEM\CurrentControlSet\Services` to install malicious drivers or hijack legitimate services. When paired with companion functions like `NtSetValueKey` or `NtOpenKey`, this API provides attackers with granular control over registry operations.

## 🛡️ Detection Opportunities
Detecting abuse of `NtCreateKey` requires more than simply flagging its presence, since legitimate applications rely on it extensively. Instead, defenders should focus on contextual and behavioral signals that distinguish suspicious activity from routine usage:

 - **Unexpected Process Origins**: Watch for `NtCreateKey` calls originating from unusual processes such as `winword.exe`, `excel.exe`, `acrord32.exe`, or browsers. These applications rarely need to create registry keys, and their use of native registry APIs should raise alarms.

 - **Suspicious Registry Paths**: Monitor for key creation in persistence related locations such as `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, `RunOnce`, `AppInit_DLLs`, or under `Services`. These paths are repeatedly abused by malware for startup execution.

 - **Direct Native API Invocation**: Track user mode applications that bypass `RegCreateKeyEx` in favor of `NtCreateKey`. This behavior is common in malware attempting to avoid higher level API hooks.

 - **Anomalous Access Patterns**: Flag sequences where a process calls `NtCreateKey`, immediately sets values (`NtSetValueKey`), and then closes the handle. This tightly coupled sequence often signals a persistence implant being written.

 - **Privilege Context**: Pay special attention to processes running under elevated contexts (`SYSTEM` or `Administrator`) creating or modifying registry keys. This activity can suggest driver installation or manipulation of sensitive services.

Here are some sample YARA rules to detect suspicious use of `NtCreateKey`:

See [NtCreateKey.yar](./NtCreateKey.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
Certain behavioral patterns around `NtCreateKey` can provide strong signals of malicious use when correlated with broader activity:

 - Creation of registry keys tied to automatic execution, such as entries in Run, RunOnce, Shell Folders, or AppInit_DLLs.
 - Writing binary blobs, PowerShell scripts, or encoded payloads directly into registry values, often as a substitute for storing files on disk.
 - Registry changes that are followed by process injection events, suggesting the key is being used to launch or configure a second-stage payload.
 - Modifications to service related keys (`SYSTEM\CurrentControlSet\Services`) that result in altered drivers or hijacked service paths.
 - Repeated cycles of `NtCreateKey` paired with obfuscation tactics, such as randomized key names or use of nonstandard hives.
 - Activity where registry persistence is established in user hives during the execution of email borne malware or commodity loaders, signaling initial access tactics.

## 🦠 Malware & Threat Actors Documented Abusing NtCreateKey
This is a common API used in malware, so this is just a small sample of tools/groups that use it.

### **Ransomware**
 - AlphV/BlackCat
 - The Gentlemen
 - WannaCry

### **Commodity Loaders & RATs**
 - GozNym
 - njRAT
 - PrivateLoader

### **APT & Threat Actor Toolkits**
 - APT28
 - APT41
 - Lazarus

### **Red Team & Open Source Tools**
 - Cobalt Strike
 - Metasploit
 - PowerSploit

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `NtCreateKey`.

## 🧵 `NtCreateKey` and Friends
`NtCreateKey` rarely operates in isolation. Attackers typically combine it with APIs like `NtSetValueKey` for writing data, `NtOpenKey` for interacting with existing entries, and `NtDeleteKey` to remove traces or overwrite prior persistence methods. For defenders, tracking these related APIs in context provides a fuller picture of registry abuse. The more common `RegCreateKeyEx` sits at the Win32 layer, but its presence can sometimes indicate an attacker using standard calls before pivoting to native APIs for stealth.

## 📚 Resources
- [NtInternals: NtCreateKey](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FKey%2FNtCreateKey.html)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!