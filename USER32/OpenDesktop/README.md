# 🖥️ OpenDesktop: When Screens Lie

## 🚀 Executive Summary
Attackers love `OpenDesktop` for one reason: it cracks open alternate desktops. Like “Winlogon” where they can hide UIs, fake login prompts, or isolate payloads from the user’s view. If you see this API in the wild, someone’s likely playing hide-and-seek with the GUI.

## 🔍 What is OpenDesktop?
Windows desktops aren’t just what you see on your monitor. They’re objects in the OS that isolate graphical input/output and user interaction. Each desktop has its own clipboard, input queue, windows, and UI threads. If you want to display a window or receive keyboard input, your process needs to attach to a desktop.

## 🚩 Why It Matters
Attackers abuse alternate desktops to control that input/output space, often for stealth or deception. It’s not just about looking invisible — it’s about controlling what the user sees and doesn’t see.

`OpenDesktopA/W` lets you grab a handle to an existing desktop object in the current session. With the right access (`DESKTOP_SWITCHDESKTOP`, `DESKTOP_HOOKCONTROL`, more), you can switch to it, spawn windows on it, or spy on activity.

Desktops are Windows UI sandboxes. The default desktop is where the user hangs out. Others (like "Winlogon") are used for secure UI operations. `OpenDesktop` is the door.

## 🧬 How Attackers Abuse It
 - **Credential Harvesting**: A fake Ctrl+Alt+Del screen or a spoofed Windows logon prompt running on the "Winlogon" desktop. The attacker switches the user's session to this desktop and displays a legit looking prompt that captures credentials.
 - **Fake Lock Screens & Ransom Notes**: Some ransomware families create a new desktop (like `CreateDesktop`) and switch to it, showing their ransom note in fullscreen. Since it’s isolated, the user can’t alt-tab out, kill the window, or interact with the underlying desktop.
 - **Deceptive UIs**: Trick users into clicking buttons or entering info into spoofed UIs that look like trusted apps. This is especially useful for bypassing UAC by displaying a fake UAC prompt and harvesting elevated credentials.
 - **GUI Thread Isolation**: Run suspicious windows (like debugging consoles, keyloggers, or screen capture interfaces) on an alternate desktop to avoid detection by the user or standard monitoring tools. GUI sandboxes don’t always render alternate desktops.
 - **Input Hijacking**: Some malware monitors user input or forces interaction by switching to a desktop they control — sometimes to simulate or record keystrokes without the user noticing.

## 🛡️ Detection Opportunities
 - Log and alert on attempts to open "Winlogon" or other uncommon desktops.
 - Track desktop switches and thread-desktop assignments.
 - Look for `OpenDesktop` chained with `SwitchDesktop` or `SetThreadDesktop` in the same process.
 - Spot GUI operations in non-interactive sessions.

Here are some sample YARA rules to detect suspicious use of `OpenDesktop`:

See [OpenDesktop.yar](./OpenDesktop.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - "Winlogon" handle opened by non-system processes
 - Desktop handle + messagebox combo in malware loaders
 - GUI operations in session 0 or service contexts
 - Alternate desktop access just before login-themed UI events

## 🦠 Malware & Threat Actors Documented Abusing OpenDesktop

### **Ransomware**
 - LockerGoga

### **Commodity Loaders & RATs**
 - NanoCore
 - Agent Tesla
 - Quasar RAT

### **APT & Threat Actor Toolkits**
 - APT29
 - FIN7

### **Red Team & Open Source Tools**
 - Cobalt Strike
 - probably others?


> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `OpenDesktop`.

## 🧵 `OpenDesktop` and Friends
`OpenDesktop` rarely flies solo. It often rolls deep with `CreateDesktop`, which lets attackers spin up their own custom desktops from scratch. It is perfect for isolating fake login prompts or GUI payloads. Once a handle is open, `SetThreadDesktop` assigns it to the current thread so malware can start drawing windows or intercepting input there. `SwitchDesktop` completes the stealth trifecta by shifting the user’s view, often used to flash fake UIs or hide activity. To get broader coverage, attackers may pair it with `OpenWindowStation` to hop between window stations, and `EnumDesktops` to enumerate every possible target across a session. When you see these APIs together, someone’s likely building a shadow interface. Just out of sight.

## 📚 Resources
- [Microsoft Docs: OpenDesktop](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-opendesktopa)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!