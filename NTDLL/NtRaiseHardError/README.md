# 🛑 NtRaiseHardError

## 🚀 Executive Summary
`NtRaiseHardError` is a native NT syscall used to raise a “hard” (critical) error that can trigger interactive system dialogs or, in some circumstances, lead to a bugcheck (blue screen) when invoked with certain parameters. Legitimate uses are almost exclusively in OS components and drivers; userland invocation by arbitrary binaries is unusual and suspicious. Attackers have weaponized this API for denial-of-service, sandbox-busting, and analyst-frustration techniques. It’s short, noisy, and effective when the goal is disruption rather than stealth.

## 🔍 What is NtRaiseHardError?
`NtRaiseHardError` is an undocumented-ish NT native routine sitting in ntdll/ntoskrnl calling paths that allows code to signal fatal or critical errors to the operating system. Depending on parameters and the environment, the result can range from an interactive critical error dialog (the “This program has performed an illegal operation…” style UI in older Windows) to a full bugcheck/reboot. Because the API invokes system-level error handling, it is normally reserved for low-level components the OS trusts.

## 🚩 Why It Matters
A single call to `NtRaiseHardError` can have outsized consequences: it may induce system instability, force reboots, or produce persistent blocking dialogs, making it a reliable way to disrupt defenders and automated analysis environments. Because an attacker needs only one well-timed invocation to abort forensic collection or crash a sandbox run, the API is a low-volume, high-payoff primitive, meaningful impact requires little effort. Legitimate user applications almost never invoke this routine, so its appearance in atypical processes is a relatively distinct signal compared to noisier injection or memory-manipulation APIs. Finally, the API’s utility spans a range of abusive goals, from denial-of-service and anti-analysis to distraction and timed escalation, which makes it a versatile tool for adversaries seeking to mask or accelerate other malicious actions.

## 🧬 How Attackers Abuse It
Attackers commonly use `NtRaiseHardError` to crash sandboxes and analysis VMs: by forcing a hard error during dynamic runs they abort traces and frustrate automated inspection. They also employ it as a distraction or cover mechanism, triggering hard errors in the middle of a malicious operation (for example, while exfiltrating data or harvesting credentials) to draw attention away and buy time for cleanup. In broader sabotage or ransomware playbooks, adversaries can force reboots or persistent blocking dialogs across multiple hosts to interrupt operations and complicate recovery. Finally, actors leverage the instability this API creates for anti-forensics, corrupting or truncating logs and forcing system states that are less favorable for investigators.

## 🛡️ Detection Opportunities
 - Log native syscall invocations. EDRs and kernel telemetry that capture native syscall names (or hook `ntdll!NtRaiseHardError`) should alert when non-system binaries invoke this API.
 - Correlate with bugchecks / WER events. Raise alerts for processes that call `NtRaiseHardError` in the short window before a new bugcheck, WER report, or unexpected reboot.
 - Dynamic resolution patterns. Watch for `GetProcAddress` or dynamic symbol resolution code that resolves `NtRaiseHardError` at runtime, especially combined with anti-VM checks.
 - Parent/child and signers. High signal when unsigned user binaries, or processes running as low-integrity users, call this API; or when it’s invoked by processes that don’t normally require kernel-level error signaling.
 - Post crash cleanup activity. Look for processes that attempt to delete event logs, Windows Error Reporting artifacts, or forensic artifacts immediately after a crash.

Here are some sample YARA rules to detect suspicious use of `NtRaiseHardError`:

See [NtRaiseHardError.yar](./NtRaiseHardError.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - A nonOS signed userland process resolves and calls `NtRaiseHardError` (or invokes it via syscall stub) and a bugcheck / critical dialog follows shortly.
 - Sequence: dynamic API resolution (`GetProcAddress` / hashing) > call to `NtRaiseHardError` > system instability (reboot or WER event).
 - Presence of anti-analysis checks (`IsDebuggerPresent`, VM detection) immediately prior to raising the hard error — indicates intentional sandbox busting.
 - Attempts to modify or delete `%SystemRoot%\System32\Winevt\Logs` or `%LOCALAPPDATA%\CrashDumps` shortly after the hard error event.
 - Rapid repetition of crash inducing calls across multiple endpoints (possible coordinated DoS or lateral sabotage).

## 🦠 Malware & Threat Actors Documented Abusing NtRaiseHardError

### **Ransomware**
 - Black Basta
 - Petya

### **Commodity Loaders & RATs**
 - Discord RAT
 - Lumma Password Stealer

### **APT & Threat Actor Toolkits**
 - MuddyWater

### **Red Team & Open Source Tools**
 - Let me know if you know one.

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `NtRaiseHardError`.

## 🧵 `NtRaiseHardError` and Friends
Commonly observed or logically-related APIs you’ll want to consider when hunting:
 - `GetProcAddress` & `LoadLibrary`: For dynamic resolution of `NtRaiseHardError`
 - `NtSetValueKey` & `RegSetValueEx`: For cleanup or persistence actions post crash
 - `NtTerminateProcess` & `RtlAdjustPrivilege`: These are used in sequences where an attacker manipulates process termination and privileges before/after forcing errors.
 - `Windows Error Reporting (WER)` APIs & Event Log APIs: to correlate artifact creation and deletion around crash events
 - `NtTerminateProcess` & `NtTerminateThread`: sometimes used in the same or other disruptive toolchains

## 📚 Resources
- [undocumented.ntinternals.net: NtRaiseHardError](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FError%2FNtRaiseHardError.html)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!