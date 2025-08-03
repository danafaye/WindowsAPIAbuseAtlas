# 👻 WinStationQueryInformationW: Ghost of Windows Past

## 🚀 Executive Summary
`WinStationQueryInformationW` is the ghost of Windows Terminal Services.  It's an old-school API that quietly whispers who’s logged into which session without raising alarms. It’s like the ultimate “peek behind the curtain” for attackers and red teams who want session intel without the usual noisy footprints. But beware: it’s ancient, deprecated, and might ghost out on modern Windows versions, so only the boldest tool-writing operators still use it. For defenders, spotting its subtle fingerprints can be a game changer because this API isn’t flashy, but it’s dangerously effective. If you want to catch someone snooping around session info without making a scene, this is where you start watching.

## 🔍 What is WinStationQueryInformationW?  
Ever had to (or wanted to) pull session details from a remote Windows terminal server without launching an entire management console? Enter `WinStationQueryInformationW`. The underdog of session introspection APIs. Quiet, precise, and deeply entrenched in the legacy of Remote Desktop Services, this function lets you peek under the hood of WinStations (Windows sessions) and get structured answers back.

Developers use this API when they need to query info like the username tied to a session, session connection state, idle time, or logon time. It's handy for custom session managers, dashboards, or utilities that monitor user activity in RDS/Terminal Server environments.

**Important note:** `WinStationQueryInformationW` is not officially supported and may be altered or unavailable in future Windows versions. Microsoft recommends using `GetSystemMetrics` with the `SM_REMOTESESSION` flag to detect Remote Desktop sessions reliably, especially in modern desktop applications. 

## 🚩 Why It Matters  
Ever wonder how an attacker can figure out who’s logged in where without tipping off EDR? `WinStationQueryInformationW` is the kind of low noise, high value API that makes that possible. Tucked away in `winsta.dll`, it quietly pulls detailed session info like usernames, logon times, idle status directly from the Terminal Services stack. No need to spawn `query.exe`, touch `WMI`, or stir up `CMD` artifacts. Red teams and malware alike can use it to profile active sessions, hunt for privileged tokens, or time their access for when an admin logs in. And because it's so often overlooked by defenders, it slips under the radar in environments that focus on process based detection. It's not just a recon tool; it’s a stealthy lens into the living, breathing user landscape of a compromised box.

## 🧬 How Attackers Abuse It  
So how does `WinStationQueryInformationW` actually get used in the wild? It starts with a handle to the Terminal Server object usually `SERVERHANDLE_CURRENT` for the local box and a session ID. From there, an attacker calls the API with the `WinStationInformation` class to grab a `WINSTATIONINFORMATION` structure. *This structure holds gold: the username, domain, logon time, session state, and even idle duration.* Toss that in a loop across all active sessions (you can enumerate them with `WTSEnumerateSessionsW`), and now you’ve got a clean, silent map of who’s logged in, what they’re doing, and how long they’ve been away from their keyboard.

Used post-exploitation, this becomes a surgical recon tool:
 - Is the domain admin logged in?
 - Is their session active or idle?
 - Is there a juicy token in a disconnected session just waiting to be stolen?

All without running a single binary that defenders typically alert on. *It's living off the land, but for Terminal Services.* Combine it with `DuplicateTokenEx` or `CreateProcessAsUserW`, and you’ve got yourself a ticket to lateral movement or privilege escalation without ever dropping a file or tripping over `whoami`.

## 🛡️ Detection Opportunities  
Calls to `WinStationQueryInformationW` by unexpected processes (powershell.exe, rundll32.exe, etc.)

Enumeration loops across session IDs with `WinStationInformation` or `WinStationUserToken`

`winsta.dll` loaded in non RDS related processes

Follow-up API calls like `DuplicateTokenEx`, `CreateProcessAsUserW`, or `SetThreadToken`

🛡️ Defensive moves:
 - Baseline normal usage of Terminal Services APIs
 - Alert on rare binaries calling this API
 - Correlate session recon with token theft behavior

Here are some sample YARA rules to detect suspicious use of `WinStationQueryInformationW`:

See [WinStationQueryInformationW.yar](./WinStationQueryInformationW.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators  
 - Looping through Session IDs: Calls to `WinStationQueryInformationW` in rapid succession with incrementing session IDs classic sign of session enumeration.  
 - Non-RDS Processes Accessing Terminal Services APIs: powershell.exe, wscript.exe, cmd.exe, or post-exploitation frameworks loading winsta.dll or invoking this API are unusual and worth flagging.  
 - Recon Followed by Token Abuse: `WinStationQueryInformationW` followed closely by `DuplicateTokenEx`, `CreateProcessAsUserW`, or `SetThreadToken`; signals privilege pivot attempts based on session info.  
 - Hunting for Disconnected or Idle Sessions: Usage of the `WinStationInformation` class to find disconnected sessions with high-privilege users, often to target abandoned but valuable tokens.  
 - Usage Outside Normal Contexts: Scripts or binaries running under SYSTEM or high-integrity users querying session info outside of login or Terminal Services contexts.

## 🦠 Malware & Threat Actors Documented Abusing WinStationQueryInformationW  

I was surprised to find that `WinStationQueryInformationW` isn't in the usual suspects ... not Emotet, not Qakbot, not even Cobalt Strike, not even banking trojans or ransomware builders off GitHub. And that’s not because it isn’t useful. It’s probably because it’s too specific/niche. Most commodity malware prioritizes mass deployment, low friction execution, and broadly compatible recon (like whoami, NetWkstaUserEnum, or WMI queries). In contrast, `WinStationQueryInformationW` is a niche Terminal Services API buried in `winsta.dll`, mostly relevant in multi session environments or RDP heavy infrastructures. It's not that the API isn’t dangerous. It’s just that most malware doesn’t bother asking who’s home before kicking the door in.

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `WinStationQueryInformationW`.

## 🧵 `WinStationQueryInformationW` and Friends  
`WinStationQueryInformationW` isn’t the only way to snoop on who's logged in. It’s just the quietest. If an attacker doesn’t mind leaving louder footprints, they might reach for `WTSEnumerateSessionsW` + `WTSQuerySessionInformationW`, which pull similar session metadata but route through the friendlier `wtsapi32.dll`. Want more legacy flavor? `NetSessionEnum` or `NetWkstaUserEnum` can show active sessions across a domain or network. Need something universal? WMI's `Win32_LogonSession` and `Win32_LoggedOnUser` classes will do the job with all the XML noise that comes with them. Even `query user` under the hood calls down to similar territory. The difference? `WinStationQueryInformationW` skips the ceremony, avoids obvious telemetry, and talks straight to the Terminal Services core making it ideal for adversaries who want session intel without setting off alarms.

## 📚 Resources  
- [Microsoft Docs: WinStationQueryInformationW](https://learn.microsoft.com/en-us/previous-versions/aa383827(v=vs.85))  
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)  

> Open a PR or issue to help keep this list up to date!
