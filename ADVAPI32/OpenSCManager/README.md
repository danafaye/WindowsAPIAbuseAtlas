# 🧰 OpenSCManager: Window's Service Control

## 🚀 Executive Summary
`OpenSCManager` is the gateway to the Service Control Manager (SCM) on Windows. It allows programs to interact with installed services whether that's querying their state, modifying them, or installing new ones. For adversaries, this API is a key foothold for achieving persistence, privilege escalation, and even execution. Abuse of `OpenSCManager` is extremely common across malware families, red team tools, and living-off-the-land binaries.

## 🔍 What is OpenSCManager?
`OpenSCManager` is a Win32 API that opens a handle to the Service Control Manager (SCM) database on a local or remote machine. This handle is the key to managing Windows services. It’s the required starting point for any meaningful service related actions. The function takes three parameters: the target machine (or NULL for local access), the name of the SCM database (almost always NULL), and a set of access rights like `SC_MANAGER_CONNECT`, `SC_MANAGER_CREATE_SERVICE`, or `SC_MANAGER_ALL_ACCESS`.

Once a handle is in hand, it unlocks a wide array of capabilities. Attackers (and administrators alike) can use it to create new services via `CreateService`, start them with `StartService`, or tear them down with `DeleteService`. They can enumerate running services using `EnumServicesStatus`, modify existing ones with `ChangeServiceConfig`, or stop security tools by calling `ControlService`. In this sense, `OpenSCManager` functions like a master key; it's quiet on its own, but essential for unlocking powerful service control primitives used in both legitimate administration and malicious tradecraft.

## 🚩 Why It Matters
Service abuse is a time tested technique for both persistence and privilege escalation. Because OpenSCManager is required to do anything meaningful with services, it’s a frequent first step. Malware uses it to install itself as a service. Red teams use it to escalate privileges. Attackers use it to manipulate legitimate services for stealthy code execution or to disable security tools. Its versatility and the fact that it’s part of normal system administration workflows makes detection tricky but critical.

## 🧬 How Attackers Abuse It
 - Create malicious services via `CreateService` after obtaining an SCM handle
 - Modify existing services by calling `ChangeServiceConfig`
 - Delete services with `DeleteService`
 - Stop or disable security related services like AV or EDR
 - Enumerate services for reconnaissance using `EnumServicesStatus`
 - Achieve remote code execution by creating services on remote machines

## 🛡️ Detection Opportunities
Monitoring usage of `OpenSCManager`isn’t enough on its own. It’s often used legitimately, but in combination with other service control APIs, it becomes a powerful indicator of compromise.

Here are some sample YARA rules to detect suspicious use of `OpenSCManager`:

See [OpenSCManager.yar](./OpenSCManager.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - Calls to `OpenSCManager` followed by `CreateService`, `StartService`, or `ChangeServiceConfig` in short succession
 - Access attempts to remote SCM (non-NULL `lpMachineName`)
 - Access with high privileges like `SC_MANAGER_ALL_ACCESS`
 - Use of `sc.exe` or `PowerShell` to wrap service related functionality
 - Unexpected service creation by non administrative users or unusual processes

## 🦠 Malware & Threat Actors Documented Abusing OpenSCManager

### **Ransomware**
 - Conti
 - LockerGoga
 - Ryuk

### **Commodity Loaders & RATs**
 - NjRAT
 - QuasarRAT
 - Remcos

### **APT & Threat Actor Toolkits**
 - APT29
 - Equation Group
 - Machete (APT-C-45)

### **Red Team & Open Source Tools**
 - Cobalt Strike
 - Impacket
 - Metasploit

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `OpenSCManager`.

## 🧵 `OpenSCManager` and Friends
The `OpenSCManager` function is rarely used in isolation. It's almost always followed by other service related APIs that act on the handle it returns. Common companion functions include `CreateService` for creating a new service, `StartService` to launch it, `ControlService` to stop or pause it, and `DeleteService` for removing it. Attackers may also call `ChangeServiceConfig` to modify service properties or `EnumServicesStatus` to enumerate existing services during reconnaissance. To interact with a specific service, `OpenService` is typically used after establishing a connection with `OpenSCManager`. Higher-level tooling like `sc.exe`, `net.exe`, and `PowerShell` often wraps this functionality, making it easier for both administrators and attackers to manipulate services with builtin utilities.

## 📚 Resources
- [Microsoft Docs: OpenSCManager](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagera)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!