# 🛠️ NtSuspendProcess

## 🚀 Executive Summary
`NtSuspendProcess` is the “pause” button for an entire process (not a polite request), but a kernel level stop sign that freezes all threads in their tracks. Legitimate apps use it rarely (debugging, certain admin tooling), but attackers love it for noisy, useful tricks: freezing EDRs, staging for memory dumps, pausing a service while they swap files or drop ransomware, or just making investigators’ lives mildly miserable. In short: when you see `NtSuspendProcess` pop up outside of maintenance windows or debuggers, raise an eyebrow. And maybe a flag.

## 🔍 What is NtSuspendProcess?
`NtSuspendProcess` is an undocumentedish (well, native NT API) syscall exposed by ntdll that, given a process handle, suspends every thread in that process. Unlike `SuspendThread`, which targets one thread at a time, `NtSuspendProcess` is a blunt instrument that halts the entire process context at the kernel level. It’s a favorite of low level tooling because it’s fast and atomic from the caller’s point of view.

## 🚩 Why It Matters
Suspending a process is low noise and high impact. It can:

 - Prevent a process from executing detection logic (pause an endpoint agent while you mess with its files).
 - Create a consistent snapshot for in-memory extraction or offline analysis (dumping a frozen process is cleaner).
 - Facilitate file replacement or tampering with process resources without race conditions.
 - Be used as a staging step in complex attacks (suspend, inject, resume ... rinse and repeat).

Because `NtSuspendProcess` affects the whole process, the side effects are obvious to a human investigating, but subtle enough for automated detectors to miss unless you’re explicitly watching for it.

## 🧬 How Attackers Abuse It
Attackers use `NtSuspendProcess` in several familiar patterns:

 - **The “make the defender sleep” trick**: suspend the EDR/antivirus process while you modify its binaries or quarantine directories. If the defender process is frozen, hooks and scans don’t run — deliciously convenient.
 - **The “clean snapshot” trick**: before dumping process memory or extracting credentials from a process, an attacker suspends it to avoid concurrent changes that corrupt the snapshot. This is common in credential theft and in-memory-only payload extraction.
 - **The “ransomware staging” trick**: attackers suspend critical services, swap in ransom or staging binaries, then resume, or suspend backup services so they can safely delete backups without the service restoring them during the delete.
 - **The “injection orchestration” trick**: suspend a target, write or map code into its address space, fix up threads, then resume to execute in a controlled, race-free moment.

It’s also used in some loader frameworks and red team toolkits because it’s straightforward: suspend → modify → resume. When combined with handle inheritance, token manipulation, or process masquerading, it becomes a powerful primitive in the attacker playbook.

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
Watch first for the who and what. When a non-debugging or unexpected process invokes `NtSuspendProcess` against high-value targets like lsass.exe, EDR/AV services, backup agents, or database engines, treat it as suspicious by default. Equally telling is how the call is made: a low privilege parent that somehow obtained a handle with `PROCESS_ALL_ACCESS` to suspend another process is a strong sign of privilege escalation or token stealing shenanigans. The canonical malicious choreography to look for is the:

-  `OpenProcess` → `NtSuspendProcess` → `WriteProcessMemory`/`NtMapViewOfSection` → `NtResumeProcess`

This sequence usually means someone froze a process to patch it, inject code, or create a clean memory snapshot. If you see a script host or interpreter spawn a tiny helper whose only job is to suspend another process, that odd parent child relationship is another red flag. Defenders don’t usually design tooling that way.

Context and timing matter just as much as the raw API call. Short suspension windows that are immediately followed by file writes to the suspended process’s binaries, creation of memory dump/minidump files soon after a suspension, or file/registry changes timed to the suspension all point to malicious intent (dumping credentials, swapping binaries, or wiping backups). 

Evasion techniques also show up: direct syscalls to call `NtSuspendProcess` bypass user mode hooks and telemetry, so lack of a user mode breadcrumb can be suspicious in itself. Finally, be skeptical of suspensions that “happen during maintenance”. If they don’t match known admin tooling signatures, scheduled job IDs, or change control records, they’re worth triage. Correlate with process creation events, file system writes, handle access rights, and network activity to turn a single API call into a convincing story you can act on.

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
`NtSuspendProcess` is the user-mode export in `ntdll` that does the whole process pause. There is **no** documented high level Win32 `SuspendProcess` API. The nearest documented equivalents are thread level calls like `SuspendThread`/`ResumeThread` (used for finer, per thread control). Other related primitives you’ll see in the same “pause/patch/resume” choreography include `NtResumeProcess` (the obvious counterpart), handle acquisition APIs (`OpenProcess`/`ZwOpenProcess`), and memory/remote-execution helpers (`WriteProcessMemory`, `NtCreateSection`/`NtMapViewOfSection`, `CreateRemoteThread`). Essentially `NtSuspendProcess` as a native syscall level primitive that attackers use when they need a fast, atomic process freeze; defenders should watch for this, and its thread-level cousins.

## 📚 Resources
- [ntdoc.m417z.com: NtSuspendProcess](https://ntdoc.m417z.com/ntsuspendthread)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!