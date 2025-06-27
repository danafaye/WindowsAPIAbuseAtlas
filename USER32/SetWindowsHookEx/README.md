### 🪝 SetWindowsHookEx  
### 🚀 Executive Summary  
`SetWindowsHookEx` is one of those Windows APIs that walks the line between essential and dangerous. It powers legitimate features like accessibility tools and input method editors, but it also gives attackers a ready-made injection mechanism and a front-row seat to everything a user types or clicks. Since it’s baked into the OS and relies on message hooks—a core part of how Windows GUIs work—it tends to blend in with the noise, making detection tricky. Abuse ranges from low-effort keyloggers to privilege escalation via DLL injection into high-integrity processes. Hooks like this might seem old-school, but they’re still in play across modern threat campaigns, red team toolkits, and commodity malware alike.

### 🔍 What is SetWindowsHookEx?  
`SetWindowsHookEx` lets you drop a hook into the Windows message river and watch things go by: keystrokes, mouse clicks, window events, you name it. Depending on the hook type, you can scope it to a single thread or reach across the system. If you're hooking system-wide, your callback needs to live in a DLL so it can be injected into other processes. It all starts with this API, and ends when you call `UnhookWindowsHookEx`.

### 🚩 Why It Matters  
Malware authors love `SetWindowsHookEx` because it gives them front row seats to user input and system events **without needing kernel access**. It's a solid way to capture credentials, observe behavior, or slip into other processes quietly. Blue teamers should care because this API shows up in a lot of living-off-the-land scenarios, from keyloggers to UI spoofing to lateral movement setups. If you see it in action, especially outside of expected apps like screen readers or accessibility tools, it's worth a closer look.

### 🧬 How Attackers Abuse It  
One common abuse path is **keylogging**. By registering a `WH_KEYBOARD_LL` and/or `WH_MOUSE_LL` hooks, an attacker can log every keypress or mouse click without touching a single driver. This works even on processes the attacker doesn’t control—perfect for credential theft, session hijacking, or quietly tracking user behavior. No privilege escalation required, just the right timing and access.

**Privilege escalation**: Process injection via system-wide hooks. When the hook procedure resides in a DLL and the attacker sets a system-wide hook targeting threads in high-privilege processes (like those running as admin), Windows automatically injects that DLL into the elevated process’s memory space. This behavior isn’t a bug; it’s how Windows implements hooks. While not the most surgical injection technique (since it can inject into all GUI processes on the current desktop), it’s reliable and can cross session boundaries, making it a useful method for privilege escalation and code execution.

More subtle uses involve **UI surveillance and manipulation**. With `WH_CBT` or `WH_CALLWNDPROC`, attackers can intercept or modify window events like dialog creation, focus changes, or even message box contents. This opens the door to spoofing, overlay attacks, or interfering with security prompts, all without touching the underlying application code.

### 🛡️ Detection Opportunities  

### 🔹 YARA
Check out some sample YARA rules here: [SetWindowsHookEx.yar](./SetWindowsHookEx.yar).

> **Heads up:** These rules are loosely scoped and designed for hunting and research. They're **not** meant for production detection systems that require low false positives. Please test and adjust them in your environment.


### 🔸 Behavioral Indicators
- **Unusual DLL loads into multiple GUI processes**  
  If the same unsigned or unexpected DLL shows up in Explorer, Notepad, Outlook, and Chrome all at once, that’s not normal. Hooks need their DLLs in every process they monitor. Look for weird patterns in `user32.dll` loads followed by suspicious module entries.

- **Hook registration from untrusted processes**  
  Normal apps don’t usually ask to monitor system-wide keyboard or CBT events. If a random userland binary registers a `WH_KEYBOARD_LL` or `WH_CBT` hook, especially from a temp path, start asking questions.

- **Cross-session or cross-desktop hooks**  
  Legit apps rarely reach across session boundaries with their hooks. If you see hooks coming from Session 0 or crossing into high-privilege sessions, you may be looking at escalation or lateral movement.

- **Mismatch between signer and hook target**  
  Accessibility tools might hook everything, but they’re signed and predictable. If a low-trust executable is hooking signed Microsoft processes, that’s sketchy. Look for inconsistencies in signer chains or process ancestry.

- **Message flood triggers**  
  Hooks fire on messages. If you see abnormal message rates, like 10,000 `WM_KEYDOWN`s in a second, it might be synthetic input or a faulty (or malicious) hook.

- **Hook procedures in strange places**  
  Hook DLLs should live in known locations. If a hook procedure is pointing to a DLL in `%TEMP%`, `%APPDATA%`, or somewhere in `C:\Users\Public`, that’s a red flag with a siren on top.


### 🦠 Malware & Threat Actors Documented Abusing SetWindowsHookEx

### **Ransomware**
- Eternity
- Locky

### **Commodity Loaders & RATs**
 - Async RAT
 - Babylon
 - GOSAR
 - Snake (Keylogger)

### **APT & Threat Actor Toolkits**
 - Blind Eagle
 - Kimsuky
 - Sidewinder

### **Red Team & Open Source Tools**
 - Probably all of them
 - Search github.com for lots of examples

### 📚 Resources  
- Microsoft Docs: [SetWindowsHookEx](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexw)
- MITRE: [Input Capture](https://attack.mitre.org/techniques/T1056/004/)
