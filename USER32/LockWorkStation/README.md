### 🔒 LockWorkStation  
### 🚀 Executive Summary  
`LockWorkStation` is one of those quiet APIs that doesn’t throw alarms but plays a key role in session control. It’s simple, native, and blends in with normal user behavior, making it easy to miss when used with intent. Attackers don’t need to get fancy when they can just lock the screen and buy time. For defenders, catching its misuse means paying attention to context, not just calls.

### 🔍 What is LockWorkStation?  
`LockWorkStation` is a function exported by `user32.dll` that programmatically locks the interactive user's desktop session. When called, it triggers the system to display the lock screen, requiring the user to re-authenticate before resuming access. This API effectively secures the current session without logging off or closing applications, maintaining all user processes in the background.

### 🚩 Why It Matters  
Locking the workstation might sound simple, but `LockWorkStation` is a sneaky little tool in the attacker’s playbook. It messes with who’s in control of the session and when, making it a key piece to watch when you’re tracking persistence or trying to spot evasive moves. Understanding it helps you catch when someone’s trying to freeze out the user or hide their tracks behind that lock screen.

### 🧬 How Attackers Abuse It  
Attackers call `LockWorkStation` to quickly lock the user’s session, preventing interruption while they carry out their tasks. This can happen during ransomware encryption, payload deployment, or lateral movement to keep the victim from interfering. It’s a straightforward way to maintain control over the system and reduce the chance of detection while malicious activity runs in the background.

**But Can’t the User Just Log Back In?** Yes—they can. LockWorkStation doesn’t kill processes or terminate sessions; it just throws up the lock screen. Everything keeps running in the background, including any malicious activity. As soon as the user logs back in, they're back where they left off. The goal here isn’t to lock them out for good, it’s to buy time, avoid interference, and keep things quiet while the attacker moves.

There is an [example](sample.cpp) of how this could be implemented on the Windows API Abuse Atlas github that calls `LockWorkStation` and changes the color of the desktop wallpaper to cyan.

### 🛡️ Detection Opportunities  

### 🔹 YARA
Check out some sample YARA rules here: [LockWorkStation.yar](./LockWorkStation.yar).

> **Heads up:** These rules are loosely scoped and designed for hunting and research. They're **not** meant for production detection systems that require low false positives. Please test and adjust them in your environment.


### 🔸 Behavioral Indicators
`LockWorkStation` by itself isn’t suspicious. It’s normal for users, GPOs, or screensavers to trigger it. What’s worth flagging is **who** called it and when. If a background process with no UI locks the desktop right before file encryption, credential access, or lateral movement, that’s a red flag. Track usage in non-interactive sessions, odd hours, or paired with recent file drops. It’s not noisy, but it’s not invisible either.

### 🦠 Malware & Threat Actors Documented Abusing LockWorkStation
Public details on malware, threat actors, or red teams using `LockWorkStation` are pretty scarce and honestly, that’s not too shocking. This API is subtle, requires no special permissions, and looks like normal user behavior, so it tends to fly under the radar. Plus, there are other techniques out there that get you more bang for your buck, like straight-up session hijacking or token stealing that are more effective for persistence or stealth. So while LockWorkStation can help disrupt user access, it’s usually just a side move rather than a headline grabber.

### **Ransomware**
- Conti
- RansomHub

### **Commodity Loaders & RATs**
- Chaos RAT
- Emotet/TrickBot

> **Note:** This list isn't exhaustive. Many modern malware families and offensive security tools use `LockWorkStation` for code injection and memory manipulation.

## 🧵 `LockWorkStation` and Friends
`ExitWindowsEx` and `InitiateSystemShutdownEx` can also kick users off their session, but they’re louder. Logging off or rebooting the system entirely. `SetThreadExecutionState` can mess with idle detection and prevent the screen from locking at all, flipping the script. `WTSDisconnectSession` is another one to watch. It disconnects the user session entirely, useful in RDP scenarios. Different tools, same goal: disrupt the user or control session visibility.

## 📚 Resources
Microsoft - [LockWorkStation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-lockworkstation)
[Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas) (more like this)

> **Know of more?**  
> Open a PR or issue to help keep this list up to date!
