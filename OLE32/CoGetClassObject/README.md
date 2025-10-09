# 🏭 CoGetClassObject: 

## 🚀 Executive Summary
`CoGetClassObject` is the COM workhorse that hands callers a class factory for a given CLSID so they can create instances of COM objects. It’s a subtle API, rarely front and center in malware writeups, but it sits at the hinge of many COM based attack patterns: object hijacking, surrogate-based code execution, out of process activation, and privilege escalation pathways that rely on unexpected COM activation contexts. When defenders see unexpected `CoGetClassObject` activity (especially from low privileged processes requesting objects that load code in system processes or from unusual file paths), treat it like a sniff of COM abuse: it frequently precedes persistence, lateral movement, or in-memory code execution via trusted hosts like dllhost.exe or svchost.exe.

## 🔍 What is CoGetClassObject?
`CoGetClassObject` is a COM (Component Object Model) API that, given a CLSID and context flags, returns an `IClassFactory` pointer the caller can use to instantiate COM objects. It’s the lower level activation primitive that underpins higher level helpers such as `CoCreateInstance`; callers choose activation contexts (in-process, local server, remote) and security parameters, and COM returns the class factory from the appropriate server (inproc DLL, local EXE server, or remote DCOM host). Because COM abstracts transport and loading, a single `CoGetClassObject` call can cause code from a registry configured inproc server to be loaded into the caller’s process or cause an out of process server to host the object in a privileged surrogate. That indirection is what attackers weaponize.

## 🚩 Why It Matters
`CoGetClassObject` matters because it’s the API that translates a CLSID into running code and, crucially, determines where that code runs. An attacker who can control which COM class a benign process activates (or who can manipulate the registration for a CLSID/AppID) can coerce a trusted host to load attacker code, achieve persistence via COM hijacks, or escalate by forcing activation in a higher privilege service process. Because COM activation routes are driven by registry and AppID configuration, abuse often looks like legitimate object instantiation at first glance, which makes it both powerful and stealthy.

## 🧬 How Attackers Abuse It
Attackers abuse `CoGetClassObject` in a few repeatable ways. 

- **COM hijacking**: change the inproc server path for a CLSID or register a malicious COM server and wait for a trusted binary to call CoGetClassObject and implicitly load attacker DLL code into its address space
- **Surrogate or local server abuse**: cause a privileged surrogate (dllhost.exe, a service host, or an auto elevated COM server) to instantiate the attacker controlled object so code runs with the surrogate’s privileges
- **DCOM/remote activations**: marshal interfaces across process boundaries.  This enables code to execute within an alternate session or user context. 
- **Evasion**: call `CoGetClassObject` directly to avoid higher level creation helpers that might be monitored more closely, giving attackers a thinner, quieter activation path.

## 🛡️ Detection Opportunities
Detecting malicious `CoGetClassObject` usage requires instrumenting both API calls and the COM activation surface. Flag `CoGetClassObject` (or `CoCreateInstance`/`CoCreateInstanceEx`) calls that request unexpected activation contexts (requesting `LOCAL_SERVER` or `REMOTE_SERVER` where an `INPROC_SERVER` is the norm) or that reference CLSIDs whose inproc server paths point to unusual directories (user %TEMP%, AppData, or nonstandard system folders). Correlate those activations with registry changes under CLSID/AppID keys and with DLL loads inside trusted host processes (dllhost.exe, explorer.exe, svchost.exe). 

Watch for low integrity or user facing processes making many `CoGetClassObject` calls for system registered CLSIDs, and for launches of dllhost.exe or other surrogates immediately following activation attempts. Instrumenting file system writes to CLSID/AppID registrations, unexpected inproc DLL loads into elevated processes, and sequences where a benign host loads a DLL shortly after a registry modification gives high fidelity detection signals.

Here are some sample YARA rules to detect suspicious use of `CoGetClassObject`:

See [CoGetClassObject.yar](./CoGetClassObject.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
A few practical behavioral indicators to hunt for: 
- A process calling `CoGetClassObject` (or `CoCreateInstance`) for CLSIDs that map to inproc servers located outside trusted system folders
- A trusted host process (dllhost.exe, svchost.exe, explorer.exe) that loads a DLL matching a recently changed CLSID/AppID registry value
- Low privilege processes requesting activation of CLSIDs normally used by services or system components
- Sequences where registry modifications to CLSID/AppID are followed soon after by activation calls and DLL loads in a different process
- Direct use of `CoGetClassObject` with explicit `CLSCTX` flags that force activation in another process or session (attackers will sometimes set flags to coerce a different activation path than typical application code would).

## 🦠 Malware & Threat Actors Documented Abusing CoGetClassObject

### **Ransomware**
- Babuk
- DarkSide
- Revil

### **Commodity Loaders & RATs**
- AgentTesla
- QakBot
- Venom

### **APT & Threat Actor Toolkits**
- APT28 (Fancy Bear)
- Mustang Panda
- Dark Hotel

### **Red Team & Open Source Tools**
- Cobalt Strike
- Covenant
- Metasploit

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `CoGetClassObject`.

## 🧵 `CoGetClassObject` and Friends
`CoGetClassObject` is one activation primitive in a broader COM ecosystem that attackers can hit from many angles. The obvious siblings are `CoCreateInstance` and `CoCreateInstanceEx` (the higher level activators that drive the same CLSID→server resolution). And `CoRegisterClassObject`, which lets a process advertise a class factory directly to the COM runtime. Beyond those, registry APIs (`RegCreateKeyEx`/`RegSetValueEx`) that change CLSID/AppID mappings, marshaling helpers (`CoMarshalInterface`/`CoUnmarshalInterface`) that push interfaces across process boundaries, and the `COSERVERINFO` path used by `CoCreateInstanceEx` for remote/DCOM activation all achieve the same end: move an object activation into a different host. Modern stacks add WinRT entry points (`RoGetActivationFactory` / `RoActivateInstance`) as functional equivalents. At the implementation level the effect is often the same: `CreateInstance`/`CreateInstanceEx` or a class factory’s `CreateInstance` ends up causing `LoadLibrary`/`LoadLibraryEx` in some host process, or a service hosting an AppID (created/changed via `CreateService`/`ChangeServiceConfig` and started with `StartService`) winds up loading attacker code. The common thread is control of the CLSID→server mapping and the activation route, whether you get there through `CoGetClassObject`, the higher level creators, marshaling, WinRT, registry edits, or service registration, you end up with code executing in a different host or privilege context.

## 📚 Resources
- [Microsoft Docs: CoGetClassObject](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cogetclassobject)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!