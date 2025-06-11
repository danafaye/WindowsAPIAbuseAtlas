# 🕵️ NtImpersonateThread: The Thread-Level Masquerader

## 🚀 Executive Summary

`NtImpersonateThread` lets one thread slip into another’s security context — legit for Windows services, but attackers twist it for stealthy token theft and privilege escalation. It’s a slick way to make malicious actions look like they’re coming from trusted processes, often slipping right past traditional defenses.

## 🔍 What is NtImpersonateThread?

`NtImpersonateThread` is a native API exported by `ntdll.dll` that lets one thread adopt the security context (token) of another. If the target thread has higher privileges, the calling thread can effectively "borrow" them — which makes this API a favorite for stealthy privilege escalation and blending in with legit processes.

## 🚩 Why It Matters

- **Privilege escalation:** Attackers can steal SYSTEM or admin tokens from privileged threads.
- **Lateral movement:** Used to access resources or perform actions as another user or service.
- **Evasion:** Malicious actions are performed under the guise of a legitimate, often trusted, process or service.
- **Less monitoring:** Thread-level impersonation is less visible to most security tools than process-level impersonation.

## 🧬 How Attackers Abuse It

- Find a thread running with higher privileges (SYSTEM)
- Call `NtImpersonateThread` to slip into that thread's security context
- Do the dirty work ... access files, spawn processes, or whatever, all under the borrowed identity
- Drop the impersonation when done to keep a low profile and dodge detection

## 👀 Sample Behavior

- Processes or threads making Calls to `NtImpersonateThread`, often following thread or process enumeration.
- Prior use of `OpenThread` or `GetThreadToken` to prepare for impersonation.
- Sudden privilege operations immediately after impresonation calls (like accessing sesntive files or spawning new processes)
- Reverting the thread to its original security context using `NtSetInformationThread` or similar calls to clean up and avoid detection.

## 🛡️ Detection Opportunities

### 🔹 YARA

Here are some sample YARA rules to detect suspicious use of `NtImpersonateThread`:

See [NtImpersonateThread.yar](./NtImpersonateThread.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🔹 Behavioral Indicators

 - `NtImpersonateThread` popping up in places you wouldn’t expect — like regular user apps that normally don’t mess with impersonation.
 - Spotting a pattern of checking out threads, grabbing tokens, then jumping into impersonation calls.
 - Watch out for any privileged moves right after impersonation happens.
 - Seeing `NtImpersonateThread` used alongside `DuplicateToken`, `SetThreadToken`, or `RevertToSelf` — classic combo for messing with identities.
 - Threads being impersonated that belong to SYSTEM or other high-level services.

## 🦠 Malware & Threat Actors Documented Abusing NtImpersonateThread

Below is a curated list of malware families, threat actors, and offensive tools known to abuse or patch `NtCreateSection`.  

For the latest technical write-ups, search for the malware, tool or actor name together with "NtCreateSection" on reputable security blogs, threat intelligence portals, or simply google. (Direct links are not included to reduce maintenance.)

### **Ransomware**
 - Agenda
 - LockBit
 - Magniber

### **Commodity Loaders & RATs**
 - Blister Loader
 - CherryLoader
 - DarkVision RAT
 - HijackLoader
 - IDAT Loader

### **APT & Threat Actor Toolkits**
 - APT41
 - Earth Berberoka
 - Winnti (APT17)

### **Red Team & Open Source Tools**
 - Atomic Read Team
 - Brute Ratel
 - Cobalt Strike
 - Infection Monkey
 - Metta
 - MITRE Caldera

> **Note:** This list isn’t exhaustive. Many advanced malware families and offensive security tools use `NtImpersonateThread` for stealth and privilege escalation.

## 🧵 `NtImpersonateThread` and Friends

Yes, it’s a good idea to mention `NtCreateThread` (and/or `NtCreateThreadEx`) in this context. Attackers often use thread creation APIs in combination with impersonation and token manipulation APIs to launch new threads under a stolen or elevated security context. This chaining is common in advanced privilege escalation and lateral movement techniques.

**Suggested revision:**

You'll often see `NtImpersonateThread` show up alongside other token-related APIs like `DuplicateToken`, `SetThreadToken`, `OpenThreadToken`, and `RevertToSelf`. Attackers may also chain these with thread creation APIs such as `NtCreateThread` or `NtCreateThreadEx` to launch new threads under an impersonated identity. When you spot these APIs used together, it's usually a sign of privilege escalation or other sneaky evasion tactics and worth investigating.

## 📚 Resources

- [NTAPI Undocumented Functions](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FThread%2FNtImpersonateThread.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1134/001/)

> Open a PR or issue to help keep this list up to date!