# 🛠️ AdjustTokenPrivileges

## 🚀 Executive Summary


## 🔍 What is AdjustTokenPrivileges?
`AdjustTokenPrivileges` is the lever attackers pull when they need more power than their token currently allows. By default, many high-impact privileges—like `SeDebugPrivilege` or `SeImpersonatePrivilege`—are present but dormant in an access token. This function flips them on. It doesn’t grant anything new outright; it just *activates latent capabilities*, which is often all that’s needed to move from user to SYSTEM, from sandbox to kernel, or from local to lateral. Used in combination with `OpenProcessToken` and `LookupPrivilegeValue`, it quietly clears the way for injection, impersonation, or credential access without dropping a file or lighting up a signature. It’s subtle, native, and far more dangerous than it looks.


## 🚩 Why It Matters
Both attackers and defenders need to understand `AdjustTokenPrivileges` because it’s one of those quiet enablers that rarely trips alarms but often precedes serious abuse. It’s not flashy, not noisy, and doesn’t scream “malicious”—but it’s a key step in unlocking high-value actions that would otherwise fail. Red teamers rely on it to escalate without exploits, while threat actors use it to blend privilege abuse into legitimate workflows. For defenders, missing this call in telemetry means missing the moment someone gained the keys to dump LSASS, impersonate SYSTEM, or sidestep sandbox constraints. If you’re not watching for it, you’re probably watching too late.


## 🧬 How Attackers Abuse It
Attackers abuse `AdjustTokenPrivileges` to silently elevate the capabilities of the access token they’re operating under, without changing their user context or launching anything overtly suspicious. After obtaining a handle to a process token—typically using `OpenProcessToken`—they call `AdjustTokenPrivileges` to enable dormant privileges like `SeDebugPrivilege`, which allows access to and manipulation of other processes, or `SeImpersonatePrivilege`, which opens the door to token theft and lateral movement via named pipes. It’s a favorite in privilege escalation chains, especially in post-exploitation stages where staying quiet is critical. Because the privileges often exist in the token by default, flipping them on doesn’t require special access—just the right API calls and a bit of timing. Combined with native tooling and minimal footprints, it makes for a reliable and stealthy upgrade in attacker capability.


## 👀 Sample Behavior & API Sequences
1. **Privilege Escalation via Debug Access**
   - `OpenProcessToken` → `LookupPrivilegeValue` → `AdjustTokenPrivileges` → `OpenProcess` (on SYSTEM process) → `ReadProcessMemory` / `WriteProcessMemory`
   - *Used to gain access to protected processes like LSASS for dumping or injection.*

2. **Token Theft and Impersonation**
   - `OpenProcessToken` → `LookupPrivilegeValue` → `AdjustTokenPrivileges` → `ImpersonateNamedPipeClient` / `DuplicateTokenEx` → `ImpersonateLoggedOnUser`
   - *Common in Potato-style privilege escalation and lateral movement using impersonation.*

3. **Sandbox Escape / Bypass Restrictions**
   - `OpenProcessToken` → `LookupPrivilegeValue` → `AdjustTokenPrivileges` → `CreateProcessAsUserW` / `CreateProcessWithTokenW`
   - *Used to spawn a new process with elevated token capabilities, bypassing sandbox or containment.*

4. **Driver Load for Kernel Exploitation**
   - `OpenProcessToken` → `LookupPrivilegeValue` (for `SeLoadDriverPrivilege`) → `AdjustTokenPrivileges` → `NtLoadDriver`
   - *Enables loading of malicious or unsigned drivers, especially in Bring Your Own Vulnerable Driver (BYOVD) scenarios.*

5. **System Shutdown / Destruction**
   - `OpenProcessToken` → `LookupPrivilegeValue` (for `SeShutdownPrivilege`) → `AdjustTokenPrivileges` → `ExitWindowsEx` / `InitiateSystemShutdownEx`
   - *Used by ransomware or wipers to force shutdown/reboot after payload execution.*

### 🧠 Analyst Tip:
Look for privilege-adjustment sequences that occur **outside of installers, system services, or known admin tools**. If a random user-mode binary is enabling `SeDebugPrivilege`, it's not debugging—it’s staging. `SeDebugPrivilege` is one of the most abusable and frequently targeted privileges in post-exploitation. When enabled, it grants a process the ability to open *any* process on the system, regardless of ownership, with `PROCESS_ALL_ACCESS`. That includes protected processes like LSASS, SYSTEM-level services, or even security tools themselves. In practice, this means attackers can read memory, inject shellcode, or manipulate threads in high-value targets without needing full SYSTEM privileges. It’s a key enabler for credential dumping, process hollowing, and advanced EDR evasion. The privilege exists by default in administrator tokens but is usually disabled—so all an attacker needs is `AdjustTokenPrivileges` to flip the switch. Because of its power and how quietly it can be activated, `SeDebugPrivilege` is often the *first* privilege turned on when a foothold is established.

## 🦠 Malware & Threat Actors Documented Abusing `AdjustTokenPrivileges` Patching

### Ransomware
 - BlackHunt (Lockbit derivative)
 - Hive
 - MailTo
 - Ryuk


### Commodity Loaders & RATs
 - DarkVision RAT
 - GuLoader

### APT & Threat Actor Toolkits
 - APT28 (FancyBear)
 - APT29 (CozyBear)
 - TEMP.Veles

### Red Team & Open Source Tools
 - Tokenvator
 - Sliver C2
 - Empire

## 🧵 `AdjustTokenPrivileges` and Friends
While `AdjustTokenPrivileges` is the canonical choice for enabling or disabling privileges within an access token—often to grant capabilities like `SeDebugPrivilege` or `SeImpersonatePrivilege`—it’s not the only tool in the token abuse toolkit. Attackers can opt for **`SetTokenInformation`** to modify token attributes (such as session ID or default DACL), or use **`DuplicateToken` / `DuplicateTokenEx`** in tandem with **`ImpersonateLoggedOnUser`** to craft a new token that inherits elevated privileges from an existing context. In fact, **`CreateRestrictedToken`** offers another variant: creating a copy of a token with fewer permissions, occasionally used in containment or to evade certain security controls. Although `AdjustTokenPrivileges` is unmatched in directly flipping specific privileges on or off within a token, the surrounding family of token management APIs provides numerous alternate ways to impersonate, escalate, or constrain execution contexts—making it vital to monitor token lifecycle operations, not just privilege adjustments.

### Resources
 - [Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges)
 - [MITRE](https://attack.mitre.org/techniques/T1134/)
 - [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)