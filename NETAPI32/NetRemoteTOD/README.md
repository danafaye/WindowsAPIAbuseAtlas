### ⏰ NetRemoteTOD  
### 🚀 Executive Summary  
Tucked into the dusty corners of `Netapi32.dl`l, `NetRemoteTOD` is a vintage time-sync relic that still answers when called. Reach out over SMB, and it’ll hand you a tidy bundle of system time, timezone offset, and the remote machine’s tick count. Legacy tools used it to align clocks; attackers use it to read the room.

🧭 Don’t assume obsolete means irrelevant. NetRemoteTOD still ticks.

### 🔍 What is NetRemoteTOD?  
`NetRemoteTOD` is a legacy Windows API tucked away in `Netapi32.dll`, designed to fetch the time-of-day information from a remote machine. It reaches out over the network to retrieve system time, timezone, and tick count details, wrapping them neatly into a `TIME_OF_DAY_INFO` structure. Primarily used in older administrative utilities and network auditing tools, it’s a straightforward way to synchronize or verify time across systems, especially in environments that predate modern time services like NTP. Though it's largely forgotten in contemporary development, it still sits quietly in the API arsenal, available to any process that knows where to look.

### 🚩 Why It Matters
Every tool in the Windows API arsenal is a double-edged sword, and `NetRemoteTOD` is no exception. For defenders, understanding it means spotting subtle signals hiding in plain sight, calls that rarely show up in normal telemetry but can reveal lateral movement or timing reconnaissance. For red teamers, it’s a low-noise channel to quietly probe remote systems, slipping under the radar of noisy time-sync protocols. Knowing this API sharpens your ability to detect or mimic low-level network activity that blends into the background, because sometimes the most overlooked calls are the most telling.

### 🧬 How Attackers Abuse It  
`NetRemoteTOD` calls out over SMB to grab the remote machine’s `TIME_OF_DAY_INFO` structure, a 20+ byte payload packed with system time, timezone bias, daylight flags, and tick count since boot. This isn’t your standard NTP chatter; it’s a legacy NetBIOS-era query that bypasses modern time sync protocols and fires over RPC, often escaping standard network time-monitoring tools. Because it’s rarely used by normal apps, spotting `NetRemoteTOD` calls in process telemetry or network logs can be a red flag for reconnaissance or timing checks. The tick count field gives a snapshot of system uptime, which attackers can use to detect sandboxes or virtual machines that reset often. Defenders who understand the quirks of this API can tune alerts for unusual calls or unexpected remote targets, turning a quiet legacy function into a canary in the coal mine. For red teams, it’s a stealthy probe: less noisy than ping sweeps or NTP queries, hard to distinguish from benign admin tooling if used sparingly, and a perfect low-key way to validate environment timing without raising alerts.

### 🛡️ Detection Opportunities  
 - Legitimate NetRemoteTOD calls are rare, any unexpected spikes or off-hours queries to remote systems should raise eyebrows.
 - Watch for processes calling into Netapi32.dll with remote server names outside usual infrastructure or hitting multiple targets rapidly, classic reconnaissance or lateral movement signs.
 - Network monitors should flag unusual SMB or RPC traffic patterns tied to NetRemoteTOD requests, especially clusters of timing queries preceding suspicious behavior.
 - Correlate TIME_OF_DAY_INFO tick count anomalies to spot sandbox evasion attempts exploiting uptime mismatches.
 - Keep an eye on obscure scripts or binaries invoking this call without a clear business reason, these shadows often hide malicious intent.
 - Tuning telemetry to catch these faint, quiet calls can turn this forgotten API into an early warning beacon.

### 🔹 YARA
Check out some sample YARA rules here: [NetRemoteTOD.yar](./NetRemoteTOD.yar).

> **Heads up:** These rules are loosely scoped and designed for hunting and research. They're **not** meant for production detection systems that require low false positives. Please test and adjust them in your environment.

### 🦠 Malware & Threat Actors Documented Abusing NetRemoteTOD
Tools that call `NetRemoteTOD` usually have lateral movement in mind: worms, bots, anything probing remote systems before spreading. But don’t let that narrow the lens. Just because it’s common in noisy malware doesn’t mean stealthy tools aren’t using it too. Quiet doesn’t mean clean.

### Commodity Loaders & RATs
 - Agobot (certain varients)
 - Phorpiex Botnet
 - Lioten Worm
 - Shamoon

### Red Team & Open Source Tools
 - CTFs
 - Impacket RPC
 - Metasploit

## 🧵 `NetRemoteTOD` and Friends
`NetRemoteTOD` isn’t the only way to pull time or uptime from a system, just one of the dustiest. Other Windows APIs offer similar functionality, often with more modern plumbing. `WMI` calls like `Win32_OperatingSystem.LastBootUpTime` can return system uptime remotely over `DCOM`, while `NetServerGetInfo` provides server stats that include boot time and time zone bias. `GetSystemTimeAsFileTime` or `GetTickCount64` expose local time and uptime, and with a bit of creative scripting, can be wrapped into RPC or PowerShell Remoting calls for remote use. Even `net time \\host` under the hood performs a similar time query, just through a different wrapper. Each of these alternatives comes with its own noise profile and detection footprint, but the intent is the same: know the time, know the terrain.

## 📚 Resources
 - Microsoft: [NetRemoteTOD](https://learn.microsoft.com/en-us/windows/win32/api/lmremutl/nf-lmremutl-netremotetod)
 - MITRE: [Natice API](https://attack.mitre.org/techniques/T1124/)
 - [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas) (more like this)

> **Know of more?**  
> Open a PR or issue to help keep this list up to date!
