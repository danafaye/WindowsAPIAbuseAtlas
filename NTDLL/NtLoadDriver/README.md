# 🚛 NtLoadDriver: The Swiss Army Knife of Memory Abuse

## 🧩 Executive Summary
`NtLoadDriver` is how attackers go from SYSTEM to kernel-mode royalty. It’s one of the tricks old-school rootkits used, and it still works. Load the right driver, and you can hide malware, kill security, or bend the OS to your will.

It’s can be loud if you’re watching, but blends in if you’re not. That’s what makes it dangerous, and why it still deserves your attention.


## 🧠 What is NtLoadDriver?
`NtLoadDriver` is the go-to Windows API for loading kernel drivers straight into the heart of the OS. It requires SYSTEM-level privileges to run, and when called with a driver’s registry path, it loads that driver into kernel memory, giving it full control over the system.

## 🎯 Why It Matters
Sure, `NtLoadDriver` requires SYSTEM privileges to use, but that’s exactly what makes it powerful. SYSTEM gets you userland dominance, but a driver takes you deeper. Kernel-mode drivers offer attackers capabilities that are harder (or riskier) to pull off in user mode: tampering with memory, disabling security tools, or hiding malicious activity at a lower level.

To be clear a driver isn’t the only way to do these things. But it’s a *cleaner*, more reliable, and often more dangerous path once you’re already SYSTEM. That’s why adversaries still reach for it when they want more than access. They want control.

## 💥  How Attackers Abuse It
`NtLoadDriver` is a native API that loads kernel-mode drivers, and attackers love it once they’ve got SYSTEM-level privileges. Why? Because with the right driver (malicious or vulnerable), they can gain low-level control of the system. 

Loading a driver via `NtLoadDriver` isn’t just about escalation. It’s about unlocking a different category of control. Kernel-mode access gives attackers the ability to manipulate the system *beneath* where most defenses operate.

## 🔗 Sample Behavior

- **Hide** files, processes, registry keys, and network connections  
- **Disable** or blind antivirus and EDR tools  
- **Tamper** with system behavior or monitoring data  
- **Bypass** security controls like Driver Signature Enforcement  
- **Persist** across reboots by loading at system startup  
- **Manipulate** system memory and core OS functionality

## 🕵️‍♂️ Detection Opportunities

### 🔹 YARA
Here are some sample YARA rules to detect malicious use of `NtLoadDriver`: 

See [NtLoadDriver.yar](./NtLoadDriver.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🔹 Behavioral Indicators
- Unexpected or unusual loading of kernel-mode drivers  
- Creation or modification of registry keys under `HKLM\SYSTEM\CurrentControlSet\Services\` for new drivers  
- Drivers loaded from non-standard or user-writable directories  
- Elevated processes invoking `NtLoadDriver` or related APIs  
- Sudden disappearance of processes, files, or network connections from system views  
- Unexplained crashes or system instability following driver loads  
- Changes to kernel structures or hooked system calls detected by integrity checks  
- Security tools failing to start, crashing, or showing gaps in telemetry after driver load  
- Use of known vulnerable or unsigned drivers in the environment  

## 🐛 Malware & Threat Actors Documented Abusing NtLoadDriver

### **Ransomware**
 - DOGE "Big Balls" Ransomware

### **Commodity Loaders & RATs**
 - PurpleHaze
 - HiddenGh0st
 - EDR Killers (generally)

### **APT & Threat Actor Toolkits**
 - Dixie-Playing Bootkit

### **Red Team & Open Source Tools**
 - Backstab
 - Game cheats & anti-cheat software (generally)

> **Note:** This list isn’t exhaustive. It's likley more malware families and offensive security tools use `NtLoadDriver`. As awareness grows, expect even more to adopt it.

## 📎 `NtLoadDriver` and Friends
`NtLoadDriver` is the classic move for loading kernel drivers, but it’s not the only game in town. Attackers often take a detour through the Service Control Manager (SCM), using APIs like `CreateService` and `StartService` to install and launch driver services instead. This lets them load drivers without touching `NtLoadDriver` directly, often with more persistence and flexibility.

There’s also the closely related `ZwLoadDriver`, a lower-level syscall counterpart to `NtLoadDriver`—which some attackers leverage for similar purposes, sometimes to bypass monitoring on higher-level API calls.

Some go even deeper, abusing lesser-known or undocumented syscalls to sneak drivers in under the radar. Knowing all the ways to load drivers helps defenders spot when attackers are trying to pull the same trick ... just with a different playbook.

## 📚 Resources
- [NtAPI Undocumented Functions](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> **Know of more?**  
> Open a PR or issue to help keep this list up to date!