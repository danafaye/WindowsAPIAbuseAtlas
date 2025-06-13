# 🦺 NtDeviceIoControlFile: Bypassing Security with Drivers & BYOVD

## 🚀 Executive Summary

`NtDeviceIoControlFile`  is like a backstage pass to Windows drivers. It shows up in normal system stuff, sure, but attackers use it to get around the velvet ropes, skipping logs, dodging EDR, and pulling off things higher-level APIs can’t touch. It’s a go-to for messing with drivers, gaining extra powers, or just flying under the radar.

## 🔍 What is NtDeviceIoControlFile?

`NtDeviceIoControlFile`  is a native Windows API that lets user-mode code send I/O requests directly to device drivers. It’s commonly used in Bring Your Own Vulnerable Driver (BYOVD) attacks to exploit signed kernel drivers for actions like disabling security tools or reading physical memory. Because it bypasses higher-level APIs and talks straight to drivers, it’s harder to detect and often overlooked in telemetry that focuses on Win32 APIs.

## 🚩 Why It Matters

- **Direct driver access:** Gives attackers a straight shot to talk to drivers, including shady or vulnerable ones, using IOCTLs. Perfect for BYOVD tricks or messing with kernel-mode behavior from user space.
 - > > IOCTLs (Input/Output Controls) are custom commands you can send to drivers to make them do stuff: read memory, write to disk, flip settings, whatever the driver supports. They’re super flexible, often undocumented, and perfect for sneaky behavior if you know the right codes to send.
- **EDR/AV evasion:** Skips past most user-mode hooks and monitors that watch higher-level APIs. This move shows up in pretty much every BYOVD attack that’s out to kill security tools.
- **Persistence:** Since it's deep in the kernel, this API lets attackers run code, steal creds, or shut down security tools, all while flying under the radar to stay persistent.

## 🧬 How Attackers Abuse It

## 🧬 How Attackers Abuse NtDeviceIoControlFile

- Exploit vulnerable drivers by sending specially crafted IOCTLs to crash systems, run code, or escalate privileges.  
- Tell security drivers or kernel components to disable protections or hide malware.  
- Bypass user-mode restrictions by doing stuff only possible at the kernel boundary.  
- Talk directly to device firmware (like storage or network cards) to plant persistent malware below the OS.  
- Control hardware for spying, data theft, or sabotage.  
- Send commands between user-mode malware and its kernel driver using IOCTLs codes.  
- Mess with logs or kernel data structures to cover their tracks and mess with forensic investigations.  

## 👀 Sample Behavior

- Calls to `NtDeviceIoControlFile` using documented or undocumented IOCTL codes from apps that don’t normally talk directly to drivers.  
- Chains like loading a driver (`NtLoadDriver`), opening device handles (`NtOpenFile`), then sending IOCTLs to take control or mess with the system.  
- Malware chatting with its own stealthy kernel driver to disable antivirus or security tools by sending commands that shut down protections.  
- Sample call chains
  - `NtLoadDriver` ➝ `NtOpenFile` ➝ `NtDeviceIoControlFile`
  - `NtOpenFile` ➝ `NtDeviceIoControlFile` ➝ `WriteFile` ➝ `CreateFile` (dump/exfil output)

## 🛡️ Detection Opportunities

### 🔹 YARA

> **Note:** YARA rules for this API should focus on the presence of `NtDeviceIoControlFile` strings, suspicious IOCTL codes, and proximity to driver or device-related APIs. 

See [NtDeviceIoControlFile.yar](./NtDeviceIoControlFile.yar)

### 🔹 Behavioral Indicators

- Weird `NtDeviceIoControlFile` calls from apps that usually stay out of system-level stuff.  
- Driver loading, grabbing device handles, then firing off IOCTLs in suspicious sequences.  
- Known-bad or vulnerable drivers popping up in the mix.  
- Trying to poke raw disks, physical memory, or security drivers directly.  
- Remember: user-mode and kernel-mode have to “speak the same language” to use this API—usually means they’re from the same developer. Random calls here? Big red flag for hunting.


## 🦠 Malware & Threat Actors Documented Abusing NtDeviceIoControlFile

Below is a curated (but not exhaustive) list of malware families, threat actors, and offensive tools known to abuse `NtDeviceIoControlFile`:

### **Ransomware**
- DarkBit
- LockerGoga
- RobbinHood

### **Commodity Loaders & RATs**
- Cobalt Strike (via custom BOFs or driver loaders)
- DopplePaymer
- Mimikatz (when using driver-based modules)

### **APT & Threat Actor Toolkits**
- APT41 (driver-based privilege escalation)
- FIN6
- Lazarus
- Winnti

### **Red Team & Open Source Tools**
- EDRKill tools
- Custom driver loaders

> **Note:** Many modern malware and offensive tools use `NtDeviceIoControlFile` for stealthy driver interaction and kernel abuse.

## 🧵 `NtDeviceIoControlFile` and Friends

`NtDeviceIoControlFile` isn’t the only way for user-mode code to talk to drivers. It’s just one flavor. You’ll see the same behavior show up in cousins like `DeviceIoControl` (the high-level wrapper), `ZwDeviceIoControlFile` (same core, different name), and sometimes even `NtReadFile` or `NtWriteFile` when attackers are moving data to or from a driver. 

## 📚 Resources

- [Microsoft Docs: NtDeviceIoControlFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntdeviceiocontrolfile)
- [loldrivers.io](https://www.loldrivers.io/) (list of known bad/vulnerable drivers)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas) (more like this)

> **Know of more?**  
> Open a PR or issue to help keep this list up to date!