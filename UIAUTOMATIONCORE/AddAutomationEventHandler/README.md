# 🔭 AddAutomationEventHandler: Malware's New Spyglass

## 🚀 Executive Summary
`AddAutomationEventHandler` enables silent observation of user interface activity through the Windows UI Automation framework. *Previously unseen in malware, it has gained attention following its use by the Coyote banking trojan*, signaling broader interest in this low noise alternative to traditional input capture. By registering for UI event notifications, such as focus shifts or text edits, malware can monitor user behavior and extract credentials without injecting into target processes or using system hooks. The technique leverages legitimate inter-process communication, allowing malware to interact with or surveil other applications while remaining stealthy and evasive. This allows the attacker to achieve persistent, undetected data exfiltration and control, often bypassing common endpoint security measures.

## 🔍 What is AddAutomationEventHandler?
`AddAutomationEventHandler` registers a callback for a specified UI Automation event on a target element. It is part of the UI Automation framework and enables programs to receive notifications about changes in the user interface, including property updates, focus transitions, and control-specific actions. This API supports event-driven monitoring of UI state, commonly used in accessibility tools and automated testing.

## 🚩 Why It Matters
This API enables passive observation of user activity by subscribing to UI Automation events without requiring injection, hooking, or visibility to the user. It offers a stealthy vector for tracking interactions within other processes, including credential fields and browser sessions. Familiarity with its behavior and misuse potential can help defenders identify anomalous access patterns indicative of surveillance or interaction hijacking.

## 🧬 How Attackers Abuse It
Malware typically begins by initializing the COM-based UI Automation framework via `CoInitialize` or `CoInitializeEx`, then acquires a pointer to the `IUIAutomation` interface (`{ff48dba4-60ef-4201-aa87-54103eef594e}`) using [`CoCreateInstance`](../OLE32/CoCreateInstance/). 

From there:
- The malware locates a target UI element using methods like `GetRootElement` or `ElementFromHandle`.
- It may then enumerate children via `FindFirst` or `FindAll`, filtering by properties like `ControlType_Edit`, `Name`, or `AutomationId`.
- Once an element of interest (e.g., a login field) is found, the malware registers a callback using `AddAutomationEventHandler`.

The event handler receives asynchronous callbacks for specified events, such as:
- `UIA_Text_TextChangedEventId`
- `UIA_AutomationFocusChangedEventId`

These are scoped to the element or its subtree and implemented in a custom `IUIAutomationEventHandler`. This enables detailed observation of user actions (text input, focus shifts, control interactions) without direct interference in the target process.

Because UI Automation can access UI elements across process boundaries—including elevated ones—attackers may pair this with UIAccess flag abuse or accessibility privilege escalation. Its reliance on legitimate COM interfaces makes detection difficult without instrumenting UI Automation channels directly.

## 🛡️ Detection Opportunities

YARA rules are available for identifying suspicious use of this API:

➡️ See [`AddAutomationEventHandler.yar`](./AddAutomationEventHandler.yar)

> **Note:** These rules are intended for **threat hunting** and **research**. They are broadly scoped and may generate false positives. Always test before deploying in production environments.

### 🐾 Behavioral Indicators

To detect abuse in the wild, monitor for:

- **Unusual process relationships**  
  Example: Microsoft Word attempting to register an event handler on a banking application.

- **High volume of event handler activity**  
  Frequent registration/unregistration may indicate automated monitoring.

- **Contextual anomalies**  
  Background utilities interacting with the foreground UI without clear purpose.

### 🧪 Hunting Tips
Reverse engineers can:
- Monitor API calls in sandboxes.
- Flag abnormal parameters (e.g., broad `TreeScope_Subtree`).
- Inspect binaries statically for unusual references to UI Automation APIs.
- Correlate UI automation activity with unexpected network exfiltration.

## 🦠 Malware & Threat Actors Documented Abusing AddAutomationEventHandler
`AddAutomationEventHandler` was first observed in real-world malware through its use in the **Coyote banking trojan**. This campaign used UI Automation to extract credentials from browser windows without user awareness. The attack mimics user behavior to blend into normal workflows and evade detection tools.

> While Coyote is the first confirmed malware to use this method, the stealth and utility of the technique suggest it could see broader adoption.

### **Detailed Technique Write-ups**
> Thanks to [Tomer Peled](https://www.akamai.com/blog/security-research/active-exploitation-coyote-malware-first-ui-automation-abuse-in-the-wild) for documenting this technique in detail.

- [Akamai: Coyote in the Wild — First-Ever Malware That Abuses UI Automation](https://www.akamai.com/blog/security-research/active-exploitation-coyote-malware-first-ui-automation-abuse-in-the-wild)

> **Note:** This is not an exhaustive list. Similar techniques may appear in future threats or be integrated into offensive security tools.

## 🧵 AddAutomationEventHandler and Friends
`AddAutomationEventHandler` is one of several APIs used for stealthy input capture or UI surveillance. Others include:

- **`SetWindowsHookEx`**  
  Used for installing low-level keyboard (`WH_KEYBOARD_LL`) or mouse (`WH_MOUSE_LL`) hooks across the system. Effective but noisier, often triggering detection.

- **Journaling Hooks (`WH_JOURNALRECORD`, `WH_JOURNALPLAYBACK`)**  
  Deprecated but once used to record and replay complete user sessions. Powerful, but typically requires elevated privileges and is more detectable.

These alternatives serve similar purposes but may require more aggressive techniques like code injection or system-wide presence, making `AddAutomationEventHandler` an appealing option for stealthy access.

## 📚 Resources
- [Microsoft Docs: AddAutomationEventHandler](https://learn.microsoft.com/en-us/windows/win32/api/uiautomationclient/nf-uiautomationclient-iuiautomation-addautomationeventhandler)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)
- [The Hacker News: New Coyote Malware Variant Exploits Windows UI Automation](https://thehackernews.com/2025/07/new-coyote-malware-variant-exploits.html)

> ⚠️ Open a PR or issue to help keep this page up to date.
