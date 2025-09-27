# 🛠️ NtSuspendProcess

## 🚀 Executive Summary
`NtSuspendProcess` is the blunt, kernel level “pause” button that freezes every thread in a process. Legit toolchains use it rarely (debuggers, some admin utilities); adversaries use it predictably: stall EDRs, create clean memory snapshots, pause services to swap binaries, or just add friction to investigations. If you see NtSuspendProcess outside of known maintenance windows or debugger contexts, treat it as suspicious until proven otherwise.

## 🔍 What is NtSuspendProcess?
`NtSuspendProcess` is an undocumentedish (well, native NT API) syscall exposed by ntdll that, given a process handle, suspends every thread in that process. Unlike `SuspendThread`, which targets one thread at a time, `NtSuspendProcess` is a blunt instrument that halts the entire process context at the kernel level. It’s a favorite of low level tooling because it’s fast and atomic from the caller’s point of view.

## 🚩 Why It Matters
A process wide suspension is low volume but high impact: it can stop detection logic from running, produce consistent memory images for credential theft or analysis, and remove race conditions needed to reliably patch or replace binaries. Those properties make the call a compact indicator of hostile intent when it targets security products, credential stores (LSASS), backup/restore services, or when it appears in unusual parent/child contexts.

## 🧬 How Attackers Abuse It
Adversaries use a tight choreography: acquire a handle (often `OpenProcess/ZwOpenProcess`), call `NtSuspendProcess` to freeze the target, perform writes or memory mapping (patch, inject, dump), then call `NtResumeProcess` or terminate the target. Common motifs are suspending EDR/AV processes to modify files or disable hooks, suspending LSASS to extract credentials via a clean dump, suspending backup services to delete backups safely, and suspending services while swapping in ransom or staging binaries. Many loaders and red-team tools implement “suspend → modify → resume” because it’s reliable; attackers chain that with handle duplication, token ops, or direct syscalls to evade user mode monitoring.

## 🛡️ Detection Opportunities
Like we've said so many times before, detection should focus on **the context** more than the single API call. `NtSuspendProcess` itself isn’t necessarily malicious, but watching who calls it, when, and what they do while the target is suspended yields signals that matter.

Some things to look for are:

 - Calls to `NtSuspendProcess` where the caller isn’t a debugger, legitimate backup/maintenance tooling, or the system installer.

 - `NtSuspendProcess` targeting security products, credential stores (LSASS), or backup services.

 - A sequence pattern: open handle → `NtSuspendProcess` → memory writes / file operations against the suspended process → `NtResumeProcess` (or process termination).

 - Handles with unexpected access rights used to call the API (like a process opened for `PROCESS_ALL_ACCESS` by a non-privileged user process).

 - Suspicious process lifecycles: short suspension followed by suspicious writes/patches, or long suspension followed by a dump action.

Here are some sample YARA rules to detect suspicious use of `NtSuspendProcess`:

See [NtSuspendProcess.yar](./NtSuspendProcess.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
Suspensions of lsass.exe, EDR/AV services, database engines, or backup agents by unexpected callers; helpers whose only job is to obtain a handle and call `NtSuspendProcess`; the canonical malicious chain (`OpenProcess` → `NtSuspendProcess` → `WriteProcessMemory/NtMapViewOfSection` → `NtResumeProcess`); short pauses that coincide with file swaps or memory dumps; and direct syscall usage that lacks user-mode traces. Any of those deserve escalation.

## 🦠 Malware & Threat Actors Documented Abusing NtSuspendProcess

### **Ransomware**
 - NotPetya Ransomware
 - SynAck Ransomware

### **Commodity Loaders & RATs**
 - Hijack Loader
 - Remocos RAT
 - Shifu Banking Trojan

### **APT & Threat Actor Toolkits**
 - Fancy Bear
 - Lazarus Group
 - Wicked Panda

### **Red Team & Open Source Tools**
 - EDR Freeze
 - Mythic
 - Sliver

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `NtSuspendProcess`.

## 🧵 `NtSuspendProcess` and Friends
There’s no high-level Win32 `SuspendProcess`; the closest documented primitives are thread level `SuspendThread/ResumeThread`. Watch the handle acquisition and remote execution cohort: `OpenProcess/ZwOpenProcess`, `NtResumeProcess`, `WriteProcessMemory`, `NtCreateSection/NtMapViewOfSection`, and remote-execution helpers like `CreateRemoteThread`. Those APIs form the pause/patch/resume choreography — instrument them together to see the whole story.

## 📚 Resources
- [ntdoc.m417z.com: NtSuspendProcess](https://ntdoc.m417z.com/ntsuspendthread)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!