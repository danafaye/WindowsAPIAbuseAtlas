# 🔌 NtAlpcConnectPort

## 🚀 Executive Summary
This one’s a little off the beaten path. `NtAlpcConnectPort` doesn’t get the same glory as your classic process injection APIs, but it’s one of those gems buried in the internals of Windows that attackers can abuse if they’re clever enough. ALPC (Advanced Local Procedure Call) is how a ton of Windows services talk to each other under the hood ... think of it as Windows’ secret walkie-talkie system. Normally it’s service-to-service chatter, but with the right moves, you can wedge yourself into the conversation. For defenders, this is one of those APIs that rarely shows up in legitimate tooling, so seeing it in the wild should raise at least one eyebrow.

## 🔍 What is NtAlpcConnectPort?
`NtAlpcConnectPort` lives in `ntdll.dll` and it’s basically the system call that lets a client connect to an ALPC port. ALPC is Microsoft’s “upgraded” version of LPC (Local Procedure Call) faster, more flexible, and used all over the place internally by Windows services. When a process wants to talk to a service that exposes an ALPC port, it uses this API to establish the connection.

In legit land, this is how components of Windows itself get things done without dragging in sockets or RPC. But since this API is exposed to userland, attackers can poke at it too.

## 🚩 Why It Matters
Here’s the deal: ALPC is under documented, rarely instrumented, and a pain to monitor. That makes it ripe for abuse. If you can connect to an ALPC port exposed by a privileged service, you might be able to:

 - Trick it into doing work on your behalf (privilege escalation).
 - Hijack communication channels for persistence or stealthy IPC.
 - Sneak data around without going through the usual monitored channels.

Because defenders don’t have a lot of out-of-the-box coverage for ALPC, this API is a perfect example of “attack surface hiding in plain sight.”

## 🧬 How Attackers Abuse It
Attackers generally abuse `NtAlpcConnectPort` to talk to privileged services that weren’t expecting them. A common trick is abusing known ALPC endpoints that don’t properly check caller permissions. Connect to the port, send the right crafted message, and suddenly you’ve got SYSTEM doing work for you.

Historically, some Windows privilege escalation exploits have leaned on ALPC misconfigurations. Beyond that, red teamers sometimes use it for covert IPC between implants on the same host. Since most EDR tools aren’t even looking at ALPC traffic, it’s a sneaky way to move data.


## 🛡️ Detection Opportunities
The sad truth: very few defenders are watching for this API at all. That means step one is visibility, hook `ntdll!NtAlpcConnectPort` and see who’s calling it. On a normal workstation, the answer is “mostly Windows itself.” If you see random user processes or third-party binaries pulling this API in, that’s your signal.

Correlation also helps: if the process has no business performing IPC with Windows services (say, Notepad.exe), but it’s suddenly connecting to ALPC ports, you might have a problem.

Here are some sample YARA rules to detect suspicious use of `NtAlpcConnectPort`:

See [NtAlpcConnectPort.yar](./NtAlpcConnectPort.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - Unusual resolution of `NtAlpcConnectPort` via `GetProcAddress` or `LdrGetProcedureAddress`, especially in processes that don’t normally rely on ALPC.
 - Binaries that are not signed by Microsoft importing `ntdll!NtAlpcConnectPort` directly, suggesting intentional use of low-level syscalls.
 - Userland processes connecting to ALPC ports that belong to privileged services (like Task Scheduler, RPC Control objects) where such communication is not expected.
 - Sequences where ALPC connections are closely followed by privilege escalation behaviors and/or token manipulation (`AdjustTokenPrivileges`, `DuplicateTokenEx`, `ImpersonateLoggedOnUser`) or sudden changes in process integrity levels.
 - ALPC activity correlated with covert inter-process communication between implants or loaders, instead of more common IPC mechanisms like named pipes.
 - Unexpected ALPC usage from commodity applications (office suites, browsers, text editors), which typically don’t leverage these system calls.

## 🦠 Malware & Threat Actors Documented Abusing NtAlpcConnectPort

Researchers and red teamers have demonstrated detailed abuse patterns of `NtAlpcConnectPort` in academic papers and conference talks, using it for stealthy IPC and privilege escalation proofs-of-concept, even when real-world malware reports are more scarce.

### **Ransomware**
 - GandCrab

### **Commodity Loaders & RATs**
 - Mal-Netminer 
 - PowerTool
 - Winnti

### **APT & Threat Actor Toolkits**
 - APT28

### **Red Team & Open Source Tools**
 - Cobalt Strike
 - Metasploit

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `NtAlpcConnectPort`.

## 🧵 `NtAlpcConnectPort` and Friends
 - `NtAlpcSendWaitReceivePort`: actually sending/receiving data once you’re connected.
 - `NtAlpcAcceptConnectPort`: the service side of the handshake.
 - `NtAlpcCreatePort`: creating the ports that make all this possible.

These APIs together form the ALPC playground. Abuse is often about chaining them to connect, send a malicious request, and escalate.

## 📚 Resources
- [ntdoc.m417z.com: NtAlpcConnectPort](https://ntdoc.m417z.com/ntalpcconnectport)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!