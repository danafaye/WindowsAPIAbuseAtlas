# NtSetInformationThread

## 🚀 Executive Summary
**`NtSetInformationThread`** is one of those quietly powerful tricks malware uses to mess with how threads behave—usually to stay hidden from debuggers or security tools. Even though this technique has been around for years, it still shows up in modern attacks because... well, it still works. With just a single API call, malware can hide its threads, dodge suspension, or throw off analysis tools—without noisy hooks or injections. It’s not as flashy as some other evasion methods, so it often flies under the radar. In this post, I’ll walk through what this function does, how attackers use it, and what defenders should watch for.

## 🚩 Why It Matters

- **Under-the-radar but active:** Even though it’s a known trick, `NtSetInformationThread` abuse rarely gets highlighted in threat reports or sandbox logs. It’s usually bundled into vague “anti-debugging” tags or overlooked in favor of flashier methods.
- **Perfect for stealthy evasion:** Attackers use it to hide threads from debuggers (`ThreadHideFromDebugger`), tweak execution, or block thread suspension—all without noisy system changes or hooks.
- **Missed by many tools:** Because it’s a low-level Native API call, it often slips past EDRs and automated detections. You usually need reverse engineering to spot it.
- **Small but mighty:** This API offers malware a lightweight way to evade analysis and dynamic tools, making it popular for both common malware and advanced threats.

## 🧬 How Attackers Abuse It

### 🛡️ Anti-Debugging
A common use is calling `NtSetInformationThread` with `ThreadHideFromDebugger` (value `0x11`). This flags the thread to user-mode debuggers so they basically ignore it. Kernel-mode debuggers still see it, but many popular user-mode tools like x64dbg or OllyDbg get tripped up. Malware often does this early on to slow down analysis or reverse engineering.

### 🧬 Helping Injection
Attackers also call `NtSetInformationThread` right after creating remote or suspended threads (via `CreateRemoteThread`, `NtCreateThreadEx`, etc.) to tweak thread properties like priority, affinity, or to hide the thread entirely. This makes injected threads harder to spot by monitoring tools or user-mode hooks. Because the call goes straight to the native API, it usually flies under the radar of higher-level security tooling.

## 🧵 Sample Behavior

### Anti-Debugging Use
- Calls `NtSetInformationThread` with `ThreadHideFromDebugger` (`0x11`) early in execution.
- Targets threads within the malware’s own process to evade user-mode debuggers.
- Often paired with other anti-debugging tricks or evasive actions.
- Usually seen during the loader or initialization phase.

### Injection Facilitation Use
- Calls `NtSetInformationThread` on remote or newly created threads right after injection.
- Changes thread properties (priority, affinity, hides thread) to avoid detection.
- Happens soon after thread creation (`CreateRemoteThread`, `NtCreateThreadEx`).
- Tied to process or thread injection techniques aiming to run malicious code stealthily.

## 🛡️ Detection Opportunities

### 🔹 YARA

Check out some sample YARA rules here: [NtSetInformationThread.yar](./NtSetInformationThread.yar).

> **Heads up:** These rules are loosely scoped and designed for hunting and research. They’re **not** meant for production detection systems that require low false positives. Please test and adjust them in your environment.

### 🔸 Behavioral Indicators

Here are some signs defenders can look for when spotting misuse of `NtSetInformationThread` in both anti-debugging and injection scenarios:

#### Anti-Debugging

- Early calls to `NtSetInformationThread` soon after process start.
- Use of the `0x11` (`ThreadHideFromDebugger`) parameter.
- Target thread is usually within the same process.
- Often accompanied by calls to APIs like `IsDebuggerPresent` or timing checks.
- May avoid higher-level anti-debug APIs in favor of this stealthier native call.

#### Injection Facilitation

- Creation of threads in remote processes (`CreateRemoteThread`, `NtCreateThreadEx`, etc.).
- Immediate calls to `NtSetInformationThread` on those threads.
- Changes to thread priority, affinity, or hiding the thread to avoid detection.
- Usually seen alongside memory manipulation calls like `VirtualAllocEx` and `WriteProcessMemory`.
- Target thread handle belongs to a remote process.

**In both cases, watch for:**

- Odd or unexplained uses of `NtSetInformationThread`, especially with `0x11`.
- Sequences where thread creation, memory allocation, and thread hiding happen together.
- Calls directly to native APIs bypassing higher-level Windows functions.
- Note: Regular apps rarely call this directly.

## 🦠 Malware & Threat Actors Documented Abusing NtSetInformationThread

Below is a curated list of malware families, threat actors, and offensive tools known to abuse or patch `NtSetInformationThread` for defense evasion.  

For the latest technical write-ups, search for the malware or tool name together with "NtSetInformationThread" on reputable security blogs, threat intelligence portals, or simply google. (Direct links are not included to reduce maintenance.)

### Ransomware
- BlackCat/ALPHV
- LockBit (v2, v3, v4)
- REvil/Sodinokibi
- Hive
- Conti
- MedusaLocker
- Pandora

### Commodity Loaders & RATs
- Cobalt Strike
- Brute Ratel C4
- Sliver
- Remcos RAT
- Metasploit
- QakBot (QBot)
- IcedID
- Agent Tesla

### APT & Threat Actor Toolkits
- APT41 (Winnti)
- FIN7 (Carbanak)
- Turla
- Wizard Spider (TrickBot/Conti)
- Lazarus Group

### Red Team & Open Source Tools
- Donut
- ScareCrow
- Invoke-ReflectivePEInjection
- SharpSploit
- Covenant
- Meterpreter
- PowerSploit
- Cobalt Strike Aggressor Scripts

> **Note:** This list isn’t exhaustive. Many modern malware families and offensive security tools use `NtSetInformationThread` for stealth and evasion. As awareness grows, expect even more to adopt it.

## 🧵 `NtSetInformationThread` and Friends
**`NtSetInformationThread`** is just one member of a larger family of **`NtSetInformation*`** functions in `ntdll.dll` that allow low-level manipulation of system objects like threads, processes, and more. From a security standpoint, these functions give malware and offensive tools powerful ways to change the behavior or state of targets—whether it’s hiding threads, modifying process attributes, or bypassing detection hooks. For example, siblings like **`NtSetInformationProcess`** and **`NtSetInformationToken`** let attackers tweak process protections or privileges, while **`NtSetInformationThread`** can be used to stealthily alter thread execution or disable monitoring. Because these functions operate beneath the usual API layers, they’re favorites for evasive maneuvers and sophisticated defense evasion techniques. Keeping an eye on the entire **`NtSetInformation*`** family — not just `NtSetInformationThread` — is key to catching subtle, low-level attack behaviors before they escalate.

## 📚 Resources
[Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationthread)

> **Know of more?**  
> Open a PR or issue to help keep this list up to date!

