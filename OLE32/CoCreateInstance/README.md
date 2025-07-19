# 🛠️ CoCreateInstance: Quietly commanding system components since Windows 95

## 🚀 Executive Summary
`CoCreateInstance` is the COM API attackers use to spin up powerful system components without touching raw APIs. It’s an official backdoor to system components; launching scripts, manipulating files, calling shell objects, and poking security subsystems through trusted, registered COM classes. This API is everywhere in malware tradecraft, from macro loaders to fileless payloads, quietly doing the heavy lifting behind the scenes. Its reach and ubiquity mean you won’t catch abuse by watching direct syscalls alone. You need to watch the COM objects it wakes up.

## 🔍 What is CoCreateInstance?
`CoCreateInstance` is a core COM (**Component Object Model**) API used to instantiate and retrieve a pointer to a COM object. COM objects are reusable, binary components that expose their functionality through interfaces. These components are often used to provide system level functionality like file dialogs, scripting engines, or access to shell or network services. `CoCreateInstance` acts as a *factory*, creating instances of COM classes identified by their CLSID (Class ID/GUID) and returns interfaces specified by IID (Interface ID/GUID). This allows developers to tap into both built-in Windows capabilities and third party extensions in a modular, standardized way. Used as intended, it supports clean component based architecture across applications, services, and the Windows operating system itself.

## 🧠 Why Use COM Instead of Direct API Calls?
All developers (malware and otherwise) often favor COM objects over direct system API calls because they offer a higher-level, language-agnostic interface to complex or sensitive functionality. Rather than managing raw Win32 APIs and custom marshalling, a developer can instantiate a COM object like `Scripting.FileSystemObject` or `Shell.Application` and immediately access powerful file, process, and UI capabilities through clean, intuitive methods. COM also enables version control, and seamless interaction between components written in different languages, and from a security standpoint, this indirection means significant operations, like launching executables, modifying the filesystem, or initiating network connections, may occur via opaque, pre-wrapped components, often bypassing typical behavioral detection anchored on native API usage.

## 🚩 Why It Matters
`CoCreateInstance` is a gateway to the `Component Object Model (COM)`, allowing programs to create and interact with powerful system components without calling lower-level APIs directly. These COM objects often wrap complex or sensitive functionality like launching browsers, scripting environments, and control panels to performing file operations or interacting with the network. It's all behind a standardized interface. This indirection can obscure what the code is truly doing, making it harder for defenders to trace intent or impact. Crucially, while `CoCreateInstance` itself doesn’t require administrative rights, many of the objects it can access do, and attackers often leverage this to skirt around direct calls to sensitive functions. Understanding the role this API plays in enabling indirect access to privileged behaviors is key to spotting abuse patterns that might otherwise go unnoticed.

## 🧬 How Attackers Abuse It
`CoCreateInstance` gives attackers a direct line to the COM infrastructure, letting them spin up powerful objects with just a `CLSID` and an `IID`. That’s all it takes to land a scripting engine, trigger privileged behaviors, or abuse signed Microsoft binaries for indirect execution. This makes it a common tool for LOLBIN abuse, in-memory execution, and fileless payloads.

One of the most abused targets is `WScript.Shell` (`{72C24DD5-D70A-438B-8A42-98424B88AFB8}`), often used to call `Run()` and pop commands through a COM object instead of a direct API. Others go for `Shell.Application` (`{13709620-C279-11CE-A49E-444553540000}`), which can call `ShellExecute` and occasionally slip through UAC without user prompts. XML components like `Msxml2.XSLTemplate` (`{2933BF93-7B36-11D2-B20E-00C04F983E60}`) let attackers load transforms packed with script, essentially weaponized XSLT.

What makes `CoCreateInstance` dangerous is its reach. COM classes wrap everything from schedulers to browser objects, and most systems have hundreds of them registered. Knowing just one CLSID can be enough to unlock unintended behavior. When attackers don't want to drop binaries, they drop into COM.

### Some Commonly Abused CLSIDs

| **CLSID** | **Component / ProgID** | **Purpose / Abuse Vector** |
|-----------|-------------------------|-----------------------------|
| `{72C24DD5-D70A-438B-8A42-98424B88AFB8}` | `WScript.Shell` | Used to execute arbitrary commands via `.Run()` or `.Exec()`. Popular in macro malware, HTA, and script-based loaders. |
| `{13709620-C279-11CE-A49E-444553540000}` | `Shell.Application` | Exposes `ShellExecute` and `Explore`. Common in UAC bypass and LOLBIN-style abuse. |
| `{6ADA6342-FC53-11D0-92DB-00C04FD7C15B}` | `MMC20.Application` | Allows loading custom snap-ins, including those with embedded script. Used for LOLBIN execution. |
| `{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}` | `TaskScheduler.TaskScheduler` | Used to create and execute scheduled tasks. Common in persistence mechanisms. |
| `{9BA05972-F6A8-11CF-A442-00A0C90A8F39}` | `ShellWindows` | Allows enumeration and manipulation of Explorer/IE windows. Used to launch IE with remote content. |
| `{F414C260-6AC0-11CF-B6D1-00AA00BBBB58}` | `MSScriptControl.ScriptControl` | Instantiates a scripting engine (JScript/VBScript). Abused for in-memory script execution. |
| `{F935DC22-1CF0-11D0-ADB9-00C04FD58A0B}` | `IWshShell` | Interface for `WScript.Shell`. Exposes `.Run()` and other methods for code execution. |
| `{88D969C0-F192-11D4-A65F-0040963251E5}` | `Msxml2.DOMDocument.6.0` | Used to load and process XML. Can be abused to host XSLT with embedded scripts. |
| `{2933BF93-7B36-11D2-B20E-00C04F983E60}` | `Msxml2.XSLTemplate.3.0` | Used to create XSLT processors. Supports embedded script execution—often paired with `Msxml2.FreeThreadedDOMDocument`. |
| `{F5078F32-C551-11D3-89B9-0000F81FE221}` | `Scripting.FileSystemObject` | Used to read/write/delete files from scripts. Frequently seen in macro malware and droppers. |
| `{9E175B68-F52A-11D8-B9A5-505054503030}` | `IE.WebBrowser` | Allows HTML rendering and navigation. Abused to load remote payloads or invoke script. |
| `{0002DF01-0000-0000-C000-000000000046}` | `InternetExplorer.Application` | Launches a visible or hidden IE instance. Allows navigation to malicious payloads. |
| `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` | `ShellSecurityEditor` | Auto-elevated; can manipulate file permissions. Appears in UAC bypass chains. |
| `{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}` | `FileOperation` | Exposes file copy/move operations. Can be used to stage files or overwrite protected paths. |
| `{0000030C-0000-0000-C000-000000000046}` | `PSFactoryBuffer` | Used internally for marshaling. Sometimes observed in reflective COM object creation in memory. |
* Table provided by ChatGPT; when asked to provide a list of most commonly abused CLSIDs.


## 🛡️ Detection Opportunities
Here are some sample YARA rules to detect suspicious use of `CoCreateInstance`:

See [CoCreateInstance.yar](./CoCreateInstance.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
`CoCreateInstance` doesn’t shout. It blends in; to find abuse look for it in places it doesn’t belong: headless binaries spawning COM objects, background tasks lighting up scripting engines, or service contexts pulling `CLSIDs` tied to shell, browser, or WMI functionality. When malware spins up `IFileOperation` to manipulate files stealthily, or uses `IWbemLocator` to dig into system state, the COM layer becomes a quiet control plane. Abuse often follows a pattern: a process instantiates a high-risk object, touches registry or file system, and either spawns, injects, or phones home. Bonus signal: when the instantiation happens from a thread not created by the main binary, especially in known good processes. That’s not automation. That’s access masquerading as intent.

## 🦠 Malware & Threat Actors Documented Abusing CoCreateInstance
Abuse of `CoCreateInstance` is old-school. It’s everywhere. From Office macros spinning up Wscript.Shell to stealthy droppers quietly launching IFileOperation, this API has been in the offensive toolkit for decades. It’s so baked into tradecraft that it often fades into the background of modern writeups, even when it's the pivot point for execution. Don’t let familiarity dull your senses.

### **Ransomware**
 - Akira
 - Matanbuchus
 - Synapse

### **Commodity Loaders & RATs**
 - DBatLoader
 - Parallax
 - Remcos

### **APT & Threat Actor Toolkits**
 - APT28
 - APT41
 - APT34

### **Red Team & Open Source Tools**
 - Bloodhound
 - Metasploit
 - PowerSploit

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `CoCreateInstance` for stealth and evasion.

## 🧵 `CoCreateInstance` and Friends
Where `CoCreateInstance` goes, others usually follow. It rarely operates in isolation. Calls to `CLSIDFromProgID`, `CoInitializeEx`, and `CoGetObject` often bookend its use, helping attackers resolve COM class identifiers or bind to remote objects. In script enabled environments, `GetObject` in VBScript or `ActiveXObject` in JScript serve as language level mirrors of the same abuse. Dig deeper, and you'll often find `SysAllocString`, `VariantInit`, and `Invoke` quietly pulling the strings behind the scenes.  They are  critical scaffolding for dynamic COM interaction. Whether it’s used for browser automation (`IWebBrowser2`), file operations (`IFileOperation`), or shell manipulation (`IShellDispatch2`), `CoCreateInstance` tends to surface in clusters. Catching its accomplices can often shine a light on what would otherwise be a low-noise execution path.

## 📚 Resources
- [Microsoft Docs: CoCreateInstance](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!