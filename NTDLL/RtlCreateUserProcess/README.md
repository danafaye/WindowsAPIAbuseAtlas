# 🛠️ RtlCreateUserProcess
## 🚀 Executive Summary

`RtlCreateUserProcess` is a low-level Native API function that allows direct creation of new processes in Windows, bypassing the higher-level `CreateProcess` family of functions. Because it operates beneath the Win32 API layer, it grants fine-grained control over process creation internals like section handles, process parameters, and security attributes, which makes it particularly attractive for stealthy process creation, evasion of security hooks, and process injection scenarios.

## 🔍 What is `RtlCreateUserProcess`?

`RtlCreateUserProcess` resides in ntdll.dll and serves as a kernel-mode facing routine for creating a new user-mode process. It is typically called by `CreateProcessInternalW`, which is in turn called by `CreateProcessW` and other user-facing process creation APIs. This function sets up the environment block, allocates process and thread handles, and initializes the process parameters through `RtlCreateProcessParametersEx`. By interacting directly with the kernel object manager through native system calls, it avoids the layers of user-mode abstractions and mitigations that surround typical process creation routines.

## 🚩 Why It Matters

Because security products and EDR hooks tend to monitor the more common process creation APIs (`CreateProcessW`, `ShellExecuteExW`, others), `RtlCreateUserProcess` can be leveraged to spawn new processes in a way that circumvents these monitoring points. Its low-level nature and rare legitimate use make its invocation a red flag for malicious or stealthy behavior. Attackers and advanced tools often use it when they want to retain process creation capabilities while minimizing their observable footprint.

## 🧬 How Attackers Abuse It
Attackers abuse `RtlCreateUserProcess` to spawn payloads in a way that avoids API-level interception or userland monitoring. For example, a malicious loader can use it to create a process in a suspended state, manually map its sections, and start execution without calling `CreateProcess`. This technique can facilitate process hollowing, parent PID spoofing, and process creation from non-standard environments like within injected DLLs or from processes with limited API access. Since this API doesn’t rely on the Win32 subsystem, it can be used from contexts that intentionally avoid initializing full user-mode runtime support—ideal for evasion in early-stage payloads or custom shells.

## 🛡️ Detection Opportunities

Detection strategies should focus on identifying calls to 

`RtlCreateUserProcess` originating from untrusted or uncommon modules, such as dynamically loaded binaries or unsigned memory regions. Because it resides in ntdll.dll, monitoring for thread stacks or call traces leading into `RtlCreateUserProcess` from non-standard processes can indicate abuse. 

Behavioral correlations, such as the creation of processes without a visible parent, unusual command-line arguments, or immediately followed by NtResumeThread, can provide context for malicious intent. 

Memory forensics and ETW-based tracing of process creation can also surface instances where `RtlCreateUserProcess` was invoked directly rather than through the standard Win32 layers.

Here are some sample YARA rules to detect suspicious use of `RtlCreateUserProcess`:

See [RtlCreateUserProcess.yar](https://github.com/danafaye/WindowsAPIAbuseAtlas/blob/main/NTDLL/RtlCreateUserProcess/RtlCreateUserProcess.yar)
.

Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; NOT for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

## 🐾 Behavioral Indicators

Execution of ntdll!`RtlCreateUserProcess` by non-system processes, particularly unsigned binaries or scripts using direct system calls, is a strong indicator. 

Suspicious use often coincides with process creation anomalies, like suspended threads, mismatched parent-child relationships, and processes lacking normal startup parameters. 

Traces of `RtlCreateProcessParametersEx` or manual environment block setup preceding the call are also notable hallmarks of API abuse.

## 🦠 Malware & Threat Actors Documented Abusing `RtlCreateUserProcess`

### Ransomware
- Alphv/BlackCat
- BlueSky
- Conti (and related)

### Commodity Loaders & RATs
- Emotet
- Ghost RAT
- Emotet

### APT & Threat Actor Toolkits
- China-nexus
- Nimbus Manticore
- Subtle Snail

### Red Team & Open Source Tools
- Cobalt Stike
- Native Run POCs

Note: This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `RtlCreateUserProcess`.

## 🧵 `RtlCreateUserProcess` and Friends

`RtlCreateUserProcess` is closely related to `RtlCreateProcessParametersEx`, which builds the process environment block (PEB) and parameter structures required for execution. It also interfaces with kernel system calls like `NtCreateUserProcess` and `NtCreateSection`, forming a foundational trio for user-mode process instantiation. Other sibling functions include `RtlCreateUserThread` for thread creation and `NtResumeThread` for resuming suspended processes, both frequently paired with `RtlCreateUserProcess` in offensive code.

## 📚 Resources

- [NTAPI Undocumented Functions](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FRtlCreateUserProcess.html)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)
