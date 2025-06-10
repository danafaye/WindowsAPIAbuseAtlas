# 🧪 NtQueueApcThread: The Undercover Agent of Process Injection

## 🚀 Executive Summary

`NtQueueApcThread` abuse flies under the radar compared to more popular injection methods, but it’s just as dangerous. By queuing APCs to a target thread, attackers can sneak in and run code inside another process — all without tripping the usual alarms. It’s a slick way to bypass user-mode hooks and evade detection tools that aren’t watching closely.

## 🔍 What is NtQueueApcThread?

An `APC` (Asynchronous Procedure Call) is basically a way to sneak a function into a thread and have it run when that thread hits an alertable state, like when it’s waiting on something. Windows lets you queue up these APCs to existing threads, which is useful for legit async tasks… but also a goldmine for attackers. If you can queue your own function into someone else’s thread, you can make their process run your code, no shellcode injection needed, just a well-placed nudge.

`NtQueueApcThread` is a native Windows API meant for legit async operations, but attackers love it for the same reason. It lets you queue a function (APC) to run in another thread’s context, which makes it perfect for stealthy code injection. Malware and red teams both use it to quietly slip past security controls and execute payloads where they shouldn’t.

## 🚩 Why It Matters

- **Stealthy execution**: Instead of spinning up a new thread (which defenders watch like hawks), NtQueueApcThread lets you hijack an existing one. That means your code runs inside another process — quietly — and is much less likely to raise alarms.

- **Off-hook execution**: in the wild ... This technique shows up in some slick tradecraft, like Early Bird (execute as preamble to hooked application) and AtomBombing (execute from OS atom table), where timing and stealth are everything. It’s not just theoretical. Real-world malware uses it to great effect.

- **Hard to distinguish**: NtQueueApcThread isn’t inherently stealthy, but it’s used by plenty of legitimate software, like antivirus tools, debuggers, and system management utilities ... to run async operations. That overlap makes it tough for security tools to draw a clean line between benign and malicious use. Unless you’re looking at the what, where, and when, like APCs queuing into suspended threads with suspicious memory mappings, it’s easy for the bad stuff to blend in.

## 🧬 How Attackers Abuse It

- Get Malicious Code Injected: First up, they gotta get their malicious code (think shellcode, DLLs, anything nasty) into the target process's memory. Tools like `VirtualAllocEx` and `WriteProcessMemory` are perfect for this.
- Queue the APC: Next, they use `NtQueueApcThread` (or something similar) to shove an `APC` into a target thread’s queue, pointing right to their injected code.
- Trigger Execution: Finally, they resume the target thread (if it was suspended) or nudge it into an "alertable" state (maybe with `SleepEx`). Boom, the thread processes its APC queue, and the attacker's payload executes in the target process’s context.

## 🧵 Sample Behavior

Alright, so how do you spot this mess? When APC injection is in play, defenders might pick up on these behaviors:

- Suspicious API Sequences: Keep an eye out for `VirtualAllocEx` or `WriteProcessMemory` calls immediately followed by `NtQueueApcThread`. This combo, especially from unexpected processes, is a huge red flag.
- Threads in an Alertable State: Watch legitimate threads (especially in critical processes) frequently going "alertable" (think suspended or sleeping) and then executing new, unfamiliar code. That’s not normal.
- Code in Weird Places: You'll see malicious code running from memory regions that have no business being there, nowhere near the process's legitimate modules.

## 🛡️ Detection Opportunities

### 🔹 YARA

Here are some sample YARA rules to detect malicious use of `NtQueueApcThread`:

See [NtQueueApcThread.yar](./NtQ).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🔹 Behavioral Indicators

- Unusual use of `NtQueueApcThread` in processes that do not typically use APCs, which means pretty much all user installed software.
- Sequence of memory allocation (`VirtualAllocEx`), memory writing (`WriteProcessMemory`), and APC queuing (`NtQueueApcThread`).
- Queuing APCs to threads in a suspended or alertable state.
- Use of `NtQueueApcThread` in combination with thread resumption APIs (e.g., `ResumeThread`).
- Lack of corresponding legitimate APC routines or use in unexpected process contexts.

## 🦠 Malware & Threat Actors Documented Abusing NtQueueApcThread

Below is a curated list of malware families, threat actors, and offensive tools known to abuse or patch `NtQueueApcThread`.

For the latest technical write-ups, search for the malware, tool, or actor name together with "NtQueueApcThread" on reputable security blogs, threat intelligence portals, or simply google. (Direct links are not included to reduce maintenance.)

### **Ransomware**
- Ryuk
- Sodinokibi (REvil)

### **Commodity Loaders & RATs**
- CobaltStrike Beacon
- Metasploit Meterpreter
- Remcos RAT

### **APT & Threat Actor Toolkits**
- APT29 (Cozy Bear)
- FIN7 (Carbanak)
- Lazarus Group

### **Red Team & Open Source Tools**
- CobaltStrike
- Metasploit
- Sliver

> **Note:** This list isn’t exhaustive. Many modern malware families and offensive security tools use `NtQueueApcThread` for stealth and evasion. As awareness grows, expect even more to adopt it.

## 🧵 `NtQueueApcThread` and Friends

**`NtQueueApcThread`** is part of a family of native APIs that enable low-level thread and memory manipulation, including `NtQueueApcThreadEx`, `NtCreateThreadEx`, and `NtSetInformationThread`. Attackers often chain these APIs together for advanced injection and evasion techniques. Monitoring for the combined use of these functions can help defenders spot sophisticated attacks before they escalate.

## 📚 Resources

- [Microsoft Docs: QueueApcThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)
- [Home	NTAPI Undocumented Functions](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FAPC%2FNtQueueApcThread.html)
- [MITRE ATT&CK: Process Injection](https://attack.mitre.org/techniques/T1055/)

> **Know of more?**  
> Open a PR or issue to help keep this list up to date!