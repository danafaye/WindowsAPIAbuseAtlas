# 🛠️ CreateNamedPipe: 

## 🚀 Executive Summary
On the surface, `CreateNamedPipe` is just plumbing ... build a pipe, send some data, close it. In reality, it’s a secret back alley of Windows, tucked away in the `\\.\pipe\` namespace, where processes can pass messages beyond the prying eyes of most defenders. Used properly, it keeps legitimate software talking to itself without tripping over the network stack. Used maliciously, it’s a silent courier, shuttling payloads, keys, and commands in and out of view.

## 🔍 What is CreateNamedPipe?
When you call `CreateNamedPipe`, you’re creating a named IPC (interprocess communication) endpoint that acts like a file but exists entirely in memory. Unlike an anonymous pipe, this one can be accessed later by name, by any process (or even remote systems) with the right permissions. Think of it as a private meeting room in Windows: you pick the name, you set the rules, and it stays open until you close it. For legitimate developers, it’s a workhorse. For attackers, it’s a quiet place to scheme.

## 🚩 Why It Matters
Named pipes bypass many of the usual tripwires. They don’t leave the same traces as files, they don’t always show up in network traffic, and with a convincing name they can masquerade as just another part of the OS machinery. Once a pipe is created, it can ferry data between processes at different privilege levels, stage encrypted blobs for later execution, or act as a long lived listener waiting for a signal from its operator. The trouble is that named pipes are everywhere buried in service communications, installers, background agents, which makes picking out the hostile ones a defender’s puzzle.

## 🧬 How Attackers Abuse It
To understand how attackers weaponize `CreateNamedPipe`, it helps to picture what a named pipe really is: a dedicated mailbox in Windows that any process with the right key can open, read from, or write to. The API lets an attacker create that mailbox anywhere in the `\\.\pipe\` namespace and decide exactly who can talk to it. From there, it becomes a discreet bridge for moving data and instructions between different parts of their toolkit.

A common pattern is the “listener and client” setup. One malware component calls `CreateNamedPipe` and then quietly waits for another process to connect. When that second process arrives, the two can swap commands, share encryption keys, or hand off payloads without ever touching the network stack. This is especially useful for malware families, which may break their operation into separate modules, one for scanning files, one for encryption, one for exfiltration, all which use pipes to keep them in sync. Everything happens locally, which means network based security tools never see a single packet.

Pipes also become dangerous in privilege escalation. Many legitimate Windows services use named pipes to receive instructions from client processes. If the service runs with SYSTEM privileges but doesn’t properly authenticate who’s talking to it, an attacker in a low privileged context can connect, send crafted commands, and trick the service into doing high privileged work on their behalf.

And then there’s camouflage. Skilled operators don’t name their pipes “evilpipe123.” They borrow the names of legitimate system components things like `\\.\pipe\wkssvc` or `\\.\pipe\lsass` to blend into the noise of hundreds of legitimate pipes on a running system. Some go further and generate names that look like legitimate GUIDs or service identifiers, making them nearly indistinguishable without deeper inspection. This naming game, combined with the low visibility of named pipes in most monitoring setups, makes them one of the stealthiest IPC mechanisms in an attacker’s toolbox.

## 🛡️ Detection Opportunities
Catching malicious pipe usage requires visibility into creation events and context. Sysmon’s Event ID 17 can log the pipe name and process that made it. ETW providers can give richer detail if you’re set up for it. Look for pipes spun up by processes that don’t normally use IPC, for suspicious naming patterns, or for activity in odd places like `%TEMP%`. A pipe that sits open for hours without obvious purpose might just be a trap waiting for a client to knock.

Here are some sample YARA rules to detect suspicious use of `CreateNamedPipe`:

See [CreateNamedPipe.yar](./CreateNamedPipe.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
Unusually named pipes, especially those with random strings or misleading system like names, deserve a second look. Also look for  pipes created right before process injection, in memory execution, or other suspicious activity. Long lived pipes that never seem to get used can also be a tell sometimes the most dangerous thing is the one that looks like it’s doing nothing at all.

## 🦠 Malware & Threat Actors Documented Abusing CreateNamedPipe

### **Ransomware**
  Couldn't find any in the ransomware itself.

### **Commodity Loaders & RATs**
  BazarLoader
  TrickBot
  Quasar RAT

### **APT & Threat Actor Toolkits**
   APT29
   Lazarus Group
   OilRig

### **Red Team & Open Source Tools**
  Cobalt Strike
  Empire
  Metasploit

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `CreateNamedPipe`.

## 🧵 `CreateNamedPipe` and Friends
This call rarely works alone. It’s often followed by `ConnectNamedPipe` to wait for incoming clients, `CallNamedPipe` for a quick connect > send > receive > disconnect sequence, `WaitNamedPipe` to stall until an endpoint is ready, and `CreateFile` on the client side to join the conversation. Together, they make a tidy little IPC toolkit that works just as well for malware as it does for system services.

## 📚 Resources
  [Microsoft Docs: CreateNamedPipe](https://learn.microsoft.com/en us/windows/win32/api/winbase/nf winbase createnamedpipea)
  [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!