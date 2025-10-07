# 🛠️ NtQuerySystemInformation

## 🚀 Executive Summary
Think of `NtQuerySystemInformation` as the low level multitool of Windows recon. With one call (and a different `SystemInformationClass` value), you can pull process lists, loaded kernel modules, system handles, perf counters; basically a lot of the system’s internals. Attackers like it because it’s compact and powerful; defenders should like it too, because when it’s used oddly (bursty calls, weird callers, recon then inject patterns) it gives a tight place to hunt.

## 🔍 What is NtQuerySystemInformation?
It’s an NT layer API in ntdll.dll that fills a buffer with whatever system information you ask for. The “what” is decided by an enum `SystemProcessInformation`, `SystemModuleInformation`, `SystemHandleInformation`, and so on. Compared to the higher level `ToolHelp`/`Win32` functions, this one gives a lower level, often richer view. So instead of calling a handful of `Win32` helpers, an actor can call `NtQuerySystemInformation` a few times and get a very complete snapshot.

## 🚩 Why It Matters
Because a single native call can replace lots of higher level probing, it’s a favorite for early stage reconnaissance. If malware can see the loaded drivers, running processes, and open handles it can: avoid systems with known EDR, pick a process to inject into, locate handles or tokens to steal, or spot unsigned drivers for kernel escalation. Also, a lot of tooling focuses on higher level APIs and misses this native layer, so attackers sometimes slip under the radar.

## 🧬 How Attackers Abuse It
In the wild, you’ll see this used for straightforward recon: a loader enumerates processes and modules to fingerprint AV/EDR and decide whether to run. You’ll also see `SystemHandleInformation` polled to find handles to devices or services that can be hijacked. Often it’s reconnaissance for a second act: inject, duplicate a token, or load a dodgy driver. Sometimes it’s noisy (lots of different `SystemInformationClass` values in short order); sometimes it’s surgical (one enum value, only what’s needed, from a process that looks harmless).

## 🛡️ Detection Opportunities
You won’t always get direct visibility into native calls, but where you do, it’s gold. If you can see `ntdll!NtQuerySystemInformation` calls and which `SystemInformationClass` was requested, that gives a clear signal. If you can’t, watch for the behavior around it: processes (especially script hosts or Office children) doing low level enumeration right after spawn, repeated queries for modules/handles/processes, or a “recon then act” sequence where enumeration is followed by remote thread creation or memory writes. Static hunting for binaries that ship with strings like `NtQuerySystemInformation` or `SystemModuleInformation` helps find toolkits and unpacked payloads, but that’s noisy and needs vetting.

Here are some sample YARA rules to detect suspicious use of `NtQuerySystemInformation`:

See [NtQuerySystemInformation.yar](./NtQuerySystemInformation.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - A process (especially script hosts, Office children, unsigned binaries) calls native enumeration functions shortly after spawn.
 - Bursty queries for `SystemModuleInformation` or `SystemHandleInformation`.
 - Recon calls followed quickly by remote thread creation, injection, or handle duplication.
 - Code that inspects driver lists and then attempts to load a similarly named user driver or drop an unsigned driver.
 - Processes that attempt to open privileged handles found via `SystemHandleInformation` (like `\\Device\\SomeSvc` or `\\.\Sam`).
 - Binaries that reference many `System*` enumeration names in plain strings (common in reconnaissance toolkits).

## 🦠 Malware & Threat Actors Documented Abusing NtQuerySystemInformation

### **Ransomware**

### **Commodity Loaders & RATs**

### **APT & Threat Actor Toolkits**

### **Red Team & Open Source Tools**

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `NtQuerySystemInformation`.

## 🧵 `NtQuerySystemInformation` and Friends
People use this alongside or instead of `Win32` helpers like `CreateToolhelp32Snapshot`/`Process32First`. After locating a target with `NtQuerySystemInformation`, an actor might move to `NtQueryInformationProcess`, `ReadProcessMemory`, `NtDuplicateObject`, or token manipulation calls to actually carry out injection, credential theft, or handle hijacking.

## 📚 Resources
- [Microsoft Docs: NtQuerySystemInformation]()
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!