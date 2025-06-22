# 🛠️ CreateProcessWithTokenW: Launching Like a Local Admin (Even When You’re Not)

## 🚀 Executive Summary
`CreateProcessWithTokenW` is a high-value weapon in the attacker’s arsenal, enabling them to run malicious code under stolen or elevated user tokens with surgical precision. By hijacking tokens from privileged accounts, adversaries bypass User Account Control (UAC), evade detection, and blend malicious processes seamlessly into legitimate user sessions. This API, often paired with token theft and duplication routines, is central to stealthy privilege escalation, lateral movement, and persistence strategies. For defenders, spotting its misuse is crucial—it marks moments when attackers gain footholds with escalated privileges, making it a prime target for early detection and disruption.

## 🔍 What is CreateProcessWithTokenW?
`CreateProcessWithTokenW` is a Windows API in `advapi32.dll` that lets a process launch a new process using the security token of another user. Essentially, it enables starting a process with the identity and privileges of someone else—like SYSTEM or a domain admin—if their token can be acquired. While legitimate uses include services launching tasks under different accounts, attackers exploit it to impersonate high-privilege users and run code under those contexts.

## 🚩 Why It Matters
Seeing `CreateProcessWithTokenW` in suspicious contexts is a major red flag for defenders. It signals that an attacker may be executing code with elevated privileges, often bypassing User Account Control (UAC) and avoiding user prompts. Because it allows malicious processes to blend into normal user sessions by masquerading under stolen tokens, detecting its misuse can uncover critical stages of an attack such as token theft, privilege escalation, or lateral movement.

## 🧬 How Attackers Abuse It
Attackers combine `CreateProcessWithTokenW` with token theft APIs like `LogonUser`, `OpenProcessToken`, and `DuplicateTokenEx` to capture or clone high-privilege tokens. After adjusting privileges (like `SeAssignPrimaryTokenPrivilege`), they spawn new processes under these tokens, executing payloads stealthily with elevated rights. This approach avoids UAC prompts and visible user switches, enabling attackers to run shells, scripts, or malware while hiding the true source of execution.

## 👀 Sample Behavior & API Sequences
### 🔺 Privilege Escalation & UAC Bypass
Attackers love abusing `CreateProcessWithTokenW` to either escalate privileges or silently bypass UAC. Both tricks rely on grabbing or duplicating a high-privilege token, then spinning up a process—usually a SYSTEM shell or admin tool—without needing a password or showing any prompts.

| API Call                         | What It Does                                                    |
|----------------------------------|----------------------------------------------------------------|
| `OpenProcess` / `LogonUser`      | Grab a handle to a SYSTEM process or authenticate as an admin  |
| `OpenProcessToken` / `DuplicateTokenEx` | Steal and duplicate the token with `TOKEN_PRIMARY` access           |
| `AdjustTokenPrivileges`          | Enable key privileges like `SeAssignPrimaryTokenPrivilege`     |
| `CreateProcessWithTokenW`        | Launch an elevated process (like `cmd.exe`) using that token  |

**Very similar, but slightly different:**  
- **Privilege escalation** usually means stealing tokens from SYSTEM processes.  
- **UAC bypass** means authenticating as an admin and launching elevated processes silently.

If you see `CreateProcessWithTokenW` combined with token theft or `LogonUser`, it’s a huge red flag for post-exploitation activity.

### 🔺 Lateral Movement
This call chain looks a lot like the UAC bypass flow. Attackers use it after grabbing credentials or tokens from a remote system to impersonate domain or privileged users and move laterally. They spin up new processes under those stolen tokens to run tools, access resources, or pivot—all while blending in with normal traffic. 

| API Call                | Description                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| `LogonUser`             | Logs in with stolen domain credentials to obtain a valid access token       |
| `DuplicateTokenEx`      | Duplicates the logon token as a `TOKEN_PRIMARY` for process creation        |
| `AdjustTokenPrivileges` | Enables any necessary privileges (like `SeImpersonatePrivilege`)           |
| `CreateProcessWithTokenW` | Spawns a process (like `cmd.exe`, `powershell.exe`) under the remote user’s context |

### 🔺 Stealthy Execution
Attackers use this chain to quietly run malicious code under a high-privilege token, keeping a low profile and avoiding obvious user context changes. The payload runs under a trusted, elevated token with minimal footprints in sessions or process trees; classic for advanced post-exploitation and stealthy backdoors.


| API Call                | Description                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| `OpenProcess`           | Open a handle to a high-privilege or SYSTEM process                         |
| `OpenProcessToken`      | Retrieve the process’s access token                                         |
| `DuplicateTokenEx`      | Duplicate the token with `TOKEN_PRIMARY` rights                             |
| `SetThreadToken`        | (Optional) Impersonate the token on the current thread                      |
| `CreateProcessWithTokenW` | Launch the malicious payload or command shell under the duplicated token   |
| `WriteProcessMemory`    | (Optional) Inject shellcode or payload into the new process                 |
| `CreateRemoteThread`    | (Optional) Execute injected code stealthily                                |

## 🛡️ How to Spot CreateProcessWithTokenW Abuse

### 🔹 YARA
Here are some sample YARA rules to detect suspicious use of `CreateProcessWithTokenW':

See [CreateProcessWithTokenW.yar](./CreateProcessWithTokenW)

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

`CreateProcessWithTokenW` is a sneaky little troublemaker—but defenders have tricks up their sleeves to catch it red-handed. Here’s how to spot this stealthy move before attackers get comfortable:

- **API Call Combo:** Keep your eyes peeled for suspicious combos like `LogonUser` + `DuplicateTokenEx` + `CreateProcessWithTokenW`. That’s the hacker’s recipe for token theft followed by stealthy process creation.

- **Token Oddities:** Watch for processes launched under unexpected or mismatched tokens—like a user-level process spawning SYSTEM-level children, or weird parent-child relationships that don’t add up in process trees or Sysmon logs.

- **No UAC Prompt? No Thanks:** If a process suddenly appears elevated without a UAC prompt or consent event, it’s probably not a friendly ghost.

- **Privilege Escalation Flags:** Monitor for token privilege changes (`SeAssignPrimaryTokenPrivilege`, `SeImpersonatePrivilege`) right before process creation—that’s a red flag waving hard.

- **Suspicious Parentage:** `CreateProcessWithTokenW` abuse often involves masquerading as trusted processes. If you see something like `explorer.exe` spawning a weird admin shell, time to investigate.

- **Timeline Jumps:** Rapid-fire sequences of token-related calls followed immediately by new process creation? Classic “token hijack and deploy” dance moves.

In short: if `CreateProcessWithTokenW` is part of the story, dig deeper. Attackers rely on blending in ... your job is to shine a spotlight on their hiding spots. That said, Not all `CreateProcessWithTokenW` activity is malicious—legit tools use it too. To separate signal from noise, look for unusual parent-child relationships (like `explorer.exe` spawning `cmd.exe`), mismatched user contexts, and odd timing (like bursts during off-hours). Correlate with command-line args, binary paths, and logon events. Baseline normal usage in your environment, and treat anything outside that norm—especially involving LOLBins or unsigned executables—as high-priority for review.

## 🦠 Malware & Threat Actors Documented Abusing `CreateProcessWithTokenW` Patching

This technique has been around for quite a while (since about 2001) and is pretty well understood among security researchers and attackers alike. So, it’s a bit surprising that explicit mentions of `CreateProcessWithTokenW` don’t pop up more often in technical write-ups. The likely reason? There’s a natural bias toward highlighting new, flashy, or novel techniques in reporting. Plus, including every single detail, especially well-known ones—would make write-ups unwieldy and far more time-consuming to produce. As a result, many analyses gloss over these “classic” moves, assuming readers already get the picture or focusing on the novel twists instead.

### Ransomware
- 8Base
- Makop Ransomware

### Commondity Loaders & RATs
 - AsyncRAT 
 - NetSupport Manager RAT
 - NjRAT

### APT & Threat Actor Toolkits
 - APT41 (Barium)
 - Lazarus Group
 - Turla

### Red Team & Open Source Tools
 - Cobalt Strike
 - Metasploit Framework
 - SharpSploit
 - PowerSploit (specifically Invoke-TokeManipulation)

## 🧵 `CreateProcessWithTokenW` and Friends
`CreateProcessWithTokenW` rarely works alone in attacker toolkits—it’s part of a family of APIs that manipulate tokens and launch processes under alternate security contexts. Attackers often swap or combine it with functions like `CreateProcessAsUserW`, `CreateProcessWithLogonW`, and lower-level native calls such as `NtCreateUserProcess` to bypass restrictions or evade detection. Token-related APIs like `OpenProcessToken`, `DuplicateTokenEx`, and `SetTokenInformation` frequently pave the way by stealing or modifying access tokens before handing them off to these process creation calls. Understanding the interplay between these “friends” is key for defenders hunting stealthy privilege escalations and lateral movement, since adversaries flexibly switch between them depending on the environment and security controls in place.


### Resources
 - [Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
 - [MITRE](https://attack.mitre.org/techniques/T1134/002/)
 - [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)