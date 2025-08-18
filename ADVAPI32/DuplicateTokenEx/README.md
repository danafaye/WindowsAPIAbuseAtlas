# 🛠️ DuplicateTokenEx 

## 🚀 Executive Summary
`DuplicateTokenEx` sits at the heart of Windows privilege management. By cloning a security token with different access rights or impersonation levels, it allows one process to assume the identity of another. In legitimate contexts, this API enables services to run tasks on behalf of users. In malicious contexts, it becomes a stepping stone for privilege escalation, lateral movement, and stealthy impersonation. Attackers who gain access to even a limited token can use `DuplicateTokenEx` to transform that foothold into powerful new capabilities.

## 🔍 What is DuplicateTokenEx?
At its core, `DuplicateTokenEx` creates a new access token based on an existing one. Unlike its simpler cousin `DuplicateToken`, it gives fine grained control: the caller can define desired access rights, token type (primary vs. impersonation), and impersonation level. Primary tokens can be used to spawn processes as another user, while impersonation tokens allow a thread to temporarily act under a different security context. This flexibility makes it both indispensable for system services and highly attractive for attackers.

## 🚩 Why It Matters
Identity is everything in Windows security. Whoever controls a token effectively controls the permissions and resources associated with that identity. If an attacker can obtain a low privileged handle to a token, `DuplicateTokenEx` may let them reshape it into a fully privileged one ... For example converting a token into a primary token that can spawn SYSTEM level processes. The implications ripple outward: persistence, escalation, lateral movement, and access to protected data all become feasible.

## 🧬 How Attackers Abuse It
Attackers rarely begin with full control of a system. More often, they start in a constrained environment. Perhaps running code under the context of a low privileged user, or inside a service with limited rights. From that humble starting point, `DuplicateTokenEx` becomes a powerful lever. It allows them to take whatever token they can access and reshape it into something far more useful.

One common abuse pattern is the creation of a primary SYSTEM token from an accessible service account token. This is possible because when a service accounts runs under LocalSystem, LocalService, or NetworkService, the Windows Service Control Manager starts the service with a token that carries powerful privileges. Even if the process itself doesn't expost SYSTEM capabilities directly, its token likely already contains them. So ... by doing this, malware can spawn entirely new processes that run with the highest possible privileges, effectively breaking out of any user restrictions.

Another frequent tactic involves impersonating another user to reach resources or files normally blocked off. This can be particularly devastating in enterprise environments where service accounts often hold broad network privileges.

The real danger lies in chaining. On its own, `DuplicateTokenEx` may only produce a new token. But when combined with APIs like `CreateProcessWithTokenW` or `ImpersonateLoggedOnUser`, it enables a seamless escalation path: duplicate the token, then immediately run a malicious binary or impersonate an administrator to move laterally. This chaining turns an API meant for delegation and convenience into a core ingredient for stealthy privilege abuse.

### Impersonation Token & Primary Token
- **Impersonation Token**: Only changes the sercurity context of a single thread inside of a process. In essence the thread is borrowing the rights of the impersonated identity while it runs, but it can't be used to start anything new.

- **Primary Token**: Copies the entire identity of a process. This includes privileges, groups, and integrety level, and importantly, it CAN spawn new processes with this identity. 

## 🛡️ Detection Opportunities
Detection begins by monitoring process behavior rather than just the API call itself. Sudden calls to `DuplicateTokenEx` from processes that do not normally perform impersonation (like office applications, browsers). Chaining with process creation APIs (`CreateProcessAsUser`, `CreateProcessWithTokenW`) is especially suspicious. Threat hunters should look for unusual token duplication events paired with privilege escalation attempts or abnormal parent-child process relationships.

Here are some sample YARA rules to detect suspicious use of `DuplicateTokenEx`:

See [DuplicateTokenEx.yar](./DuplicateTokenEx.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
- Non-service processes creating primary tokens
- Token duplication followed by privileged process creation
- Execution of unusual binaries under SYSTEM or another user’s context
- Abnormal impersonation attempts from unexpected processes

## 🦠 Malware & Threat Actors Documented Abusing DuplicateTokenEx

### **Ransomware**
- BackMyData
- DragonForce
- RagnarLocker

### **Commodity Loaders & RATs**
 - 888 RAT
 - MyDoom
 - Qakbot

### **APT & Threat Actor Toolkits**
- APT28
- APT41

### **Red Team & Open Source Tools**
- PoshC2
- PowerSploit
- Sliver


> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `DuplicateTokenEx`.

## 🧵 `DuplicateTokenEx` and Friends
`DuplicateTokenEx` rarely acts alone. It frequently appears alongside `OpenProcessToken`, `ImpersonateLoggedOnUser`, `SetThreadToken`, and process creation APIs like `CreateProcessWithTokenW`. Together, these functions create a powerful toolkit for identity manipulation and privilege escalation. Tracking their combined use provides stronger signals of malicious intent than monitoring any one API in isolation.

## 📚 Resources
- [Microsoft Docs: DuplicateTokenEx]()
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!