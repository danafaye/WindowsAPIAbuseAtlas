# 👤 ImpersonateLoggedOnUser

## 🚀 Executive Summary
`ImpersonateLoggedOnUser` is one of those functions that seems harmless on the surface. It just lets a thread take on the security context of another user. In practice, though, this tiny shift in “who am I?” has massive consequences. Malware operators, penetration testers, and admins gone rogue all know that if you can impersonate a higher privileged account, you’ve essentially traded up your identity badge for one with unlimited access. This API has powered everything from token theft attacks in corporate networks to stealthy lateral movement in red team ops.

## 🔍 What is ImpersonateLoggedOnUser?
At its core, `ImpersonateLoggedOnUser` is an API in ADVAPI32.dll that takes a token (think: a little data structure that defines what a user can do) and tells the calling thread, “From now on, act like you’re this person.” Instead of launching a whole new process as another user, the thread simply borrows their identity temporarily. This means file system access, registry changes, network calls, and basically anything gated by Windows security checks are evaluated using the impersonated user’s rights. It’s like slipping on a disguise that’s convincing enough to get past the guards without anyone asking questions.

## 🚩 Why It Matters
Windows is built on the assumption that tokens represent trust. If you can manipulate a token or borrow one that doesn’t belong to you, the security model crumbles fast. Imagine a piece of malware running as a low privilege user suddenly stealing a SYSTEM token and using this API to impersonate it; instant privilege escalation. Or consider lateral movement: grab a network administrator’s token, impersonate it, and you’ve just turned a compromised endpoint into a beachhead for spreading across the domain. For defenders, this is one of those high signal APIs. Its misuse is rarely benign outside of very specific enterprise software scenarios.

## 🧬 How Attackers Abuse It
Attackers love `ImpersonateLoggedOnUser` because it closes the loop on token stealing. Tools like Mimikatz make it trivial to pull access tokens from memory. Once an attacker has a juicy token in hand, say from a domain admin who left a session open, they can feed it into this API and instantly start operating as that account. This trick shows up in malware implants that need to quietly move through a network without raising alarms, in ransomware families that escalate privileges before detonating, and in red team toolkits that mimic real adversaries to test defenses. What makes it even sneakier is that the change only affects the calling thread, so the process doesn’t obviously flip users, which makes it harder to spot unless you’re looking for it.

## 🛡️ Detection Opportunities
From a blue team perspective, catching `ImpersonateLoggedOnUser` abuse requires watching for suspicious token use. Threads suddenly running as privileged accounts when the parent process shouldn’t have access to those accounts is a huge red flag. Monitoring event logs for token operations and mapping API usage to process lineage helps. EDR products can also hook into these calls to alert when a non-admin process tries to impersonate a highly privileged token. Context matters! Legitimate enterprise apps (like IIS or SQL Server) sometimes use impersonation for delegation, but anything outside those expected baselines is worth digging into.

Here are some sample YARA rules to detect suspicious use of `ImpersonateLoggedOnUser`:

See [ImpersonateLoggedOnUser.yar](./ImpersonateLoggedOnUser.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
When `ImpersonateLoggedOnUser` is misused, the footprint is usually bigger than the call itself. Rarely does an attacker just call it in isolation. It’s almost always part of a whole sequence of API activity that screams “token abuse” if you know what to look for. Some common patterns include:

**Token Acquisition**
 - `OpenProcessToken`: grab the current process’s token
 - `OpenThreadToken`: snatch the token tied to a specific thread
 - `LogonUserA/W`: authenticate with stolen creds to generate a fresh token
 - `DuplicateToken` or `DuplicateTokenEx`: clone an existing token so it can be reused or elevated

**Impersonation**
 - `ImpersonateLoggedOnUser`: the star of the show, applying the token to the current thread
 - `SetThreadToken`: another way to assign a stolen or duplicated token to a specific thread
 - `ImpersonateNamedPipeClient`: often abused with named pipes for privilege escalation or lateral movement
 - `RevertToSelf`: called when attackers want to drop the disguise and return to their original identity

**Privilege Escalation & System Access**
 - `AdjustTokenPrivileges`: enable juicy privileges like SeDebugPrivilege or SeImpersonatePrivilege
 - `NtSetInformationToken`: tweak the token’s attributes to elevate or sidestep restrictions
 - `CreateProcessAsUser` or `CreateProcessWithTokenW`: spin up a brand-new process under the stolen identity

**Post-Impersonation Activity**
 - `RegOpenKeyEx` and/or `RegSetValueEx`: registry persistence now happening under the impersonated account.
 - `CreateFile` and/or `WriteFile`: accessing or dropping files that would’ve been restricted before.
 - `NetUseAdd` or direct SMB API calls: suddenly mapping drives or accessing admin shares with elevated rights.
 - `RpcBindingSetAuthInfoEx`: performing RPC calls with the new credentials to pivot deeper into the network.

On the network side, impersonation often bleeds into activity like SMB, WMI, or RPC traffic. If you see a nonprivileged service suddenly reaching out over SMB using a domain admin’s identity, that’s a big “uh-oh” moment. This is especially true when service accounts, which normally stay put, start showing up in lateral movement or remote execution events.

Finally, impersonation usually correlates with other attacker workflows like process injection (`WriteProcessMemory`, `CreateRemoteThread`, `NtMapViewOfSection`) or credential dumping (`LsaRetrievePrivateData`, `ReadProcessMemory`). It’s not just one call. It’s the cluster of suspicious activity around it that lights up like neon when an adversary is on the move.

## 🦠 Malware & Threat Actors Documented Abusing ImpersonateLoggedOnUser

### **Ransomware**
 - NetWalker
 - RansomHub

### **Commodity Loaders & RATs**
 - AgentTesla
 - QakBot
 - TrickBot

### **APT & Threat Actor Toolkits**
 - APT28
 - FIN8

### **Red Team & Open Source Tools**
 - MimiKatz
 - CobaltStrike

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `ImpersonateLoggedOnUser`.

## 🧵 `ImpersonateLoggedOnUser` and Friends
ImpersonateLoggedOnUser rarely operates alone. Its favorite companions are OpenProcessToken and DuplicateTokenEx, which provide the raw material—the tokens—that it needs to work. Other impersonation-related APIs like SetThreadToken and RevertToSelf also tend to show up in the same call chains. Together, they form the toolkit attackers rely on for identity theft at the system level. Think of it as a little crew: some APIs steal the mask, some APIs put it on, and this one wears it proudly to walk right past your defenses.

## 📚 Resources
- [Microsoft Docs: ImpersonateLoggedOnUser](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateloggedonuser)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!