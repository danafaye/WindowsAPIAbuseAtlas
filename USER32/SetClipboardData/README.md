# 📋 SetClipboardData: Copy, Paste, Pwned 

## 🚀 Executive Summary
`SetClipboardData` isn’t flashy, but it doesn’t need to be. It’s the quiet accomplice in clipboard hijacks, the unseen hand in copy/paste deception, and the bridge between user trust and attacker intent. Originally designed to help apps share data, it’s now a favorite for swapping Bitcoin wallet addresses, priming fake commands, and slipping payloads across RDP sessions without dropping a file. When paired with its clipboard cousins, it becomes part of a low noise, high trust abuse surface that lives right under the user’s fingertips. In the wrong hands, the clipboard isn’t just a convenience. It’s a weapon.

## 🔍 What is SetClipboardData?
`SetClipboardData` is a Windows API used to place data on the clipboard in a specified format, typically following a call to `OpenClipboard` and `EmptyClipboard`. Designed for legitimate interprocess communication, it enables applications to transfer content like text, images, or custom formats by claiming ownership of clipboard data. Once data is set, the system assumes responsibility for its lifetime. This means the application can release its handle after the call completes. While it’s most often used in GUI driven software to support copy/paste functionality, its ability to silently stage or inject data into the clipboard across desktop sessions introduces a technique that is gaining propularity for user deception, data exfiltration, or even interprocess payload transfer.

## 🚩 Why It Matters
`SetClipboardData` plays a quiet but pivotal role in user-driven data flows, bridging application boundaries with implicit trust. By writing data to the clipboard in a chosen format, it enables seamless transfer of content like text, images, binary blobs between processes without persistent storage or explicit permissions. This trust by design mechanism creates opportunities for abuse: clipboard priming for social engineering, covert staging of payloads, or lateral data movement between security contexts. In environments where clipboard contents may be accessed or processed automatically, such as RDP sessions, remote support tools, or automated workflows. Manipulation via SetClipboardData becomes more than benign functionality; it becomes a potential vector.

## 🧬 How Attackers Abuse It
`SetClipboardData` quietly enables a range of user interaction attacks. Common abuse patterns include clipboard hijacking, where malware monitors and overwrites clipboard contents by substituting copied cryptocurrency wallet addresses with attacker controlled ones. In some cases, this swap occurs milliseconds before a paste operation, making detection nearly impossible for the user. In clickjacking scenarios, malicious applications can stage misleading clipboard data to trick users into pasting commands or content they didn’t intend, often as part of broader social engineering chains. Within remote desktop or virtualized environments, clipboard synchronization across sessions offers attackers a bridge to inject payloads or exfiltrate data without touching disk. Though `SetClipboardData` is not inherently suspicious, its quiet utility makes it a reliable tool for low-noise manipulation, especially when paired with user trust and automation.

## 🛡️ Detection Opportunities
Here are some sample YARA rules to detect suspicious use of `SetClipboardData`:

See [SetClipboardData.yar](./SetClipboardData.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
While `SetClipboardData` alone doesn’t raise alarms, its context and cadence can betray intent. Clipboard interaction tied to noninteractive processes, high frequency clipboard writes, or unexpected format usage may signal something worth a second look. When clipboard manipulation intersects with user deception, exfiltration, or staged execution, the following behavioral indicators can help separate benign from suspicious:

 - Clipboard writes from background or non-GUI processes (without associated window focus or user input).
 - High-frequency or recurring calls to `SetClipboardData`, especially with `CF_TEXT` or `CF_UNICODETEXT`, outside expected application behavior.
 - Clipboard content overwritten shortly after user copy events, suggesting interception or redirection.
 - Mismatch between clipboard format advertised and actual content (mislabeled or malformed data).
 - Use of custom clipboard formats by unsigned or unusual binaries.
 - Clipboard manipulation paired with API calls like `OpenClipboard`, `GetClipboardData`, `FindWindow`, or `SendInput`.
 - Activity coinciding with RDP sessions, suggesting cross-context data injection or exfiltration.
 - Execution chains where clipboard data is used to trigger scripting or command execution (PowerShell via paste).

## 🦠 Malware & Threat Actors Documented Abusing SetClipboardData

### **Ransomware**
 - BianLian
 - DarkGate
 - Interlock

### **Commodity Loaders & RATs**
 - Agent Tesla
 - CryptoShuffler
 - Metamorfo
 - XLoader

### **APT & Threat Actor Toolkits**
 - Pioneer Kitten
 - TA571

### **Red Team & Open Source Tools**
 - Atomic Red Team
 - Empire
 - Metasploit

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `SetClipboardData`.

## 🧵 `SetClipboardData` and Friends
`SetClipboardData` rarely acts alone. It lives in a cluster of clipboard related APIs that, together, form a full read/write interface into user driven data flow. `GetClipboardData` retrieves data placed by any process, allowing adversaries to spy on user activity, extract copied credentials, or harvest staged content. `OpenClipboard` and `CloseClipboard` wrap access control, while `EmptyClipboard` clears existing data often as a prelude to overwrite. `IsClipboardFormatAvailable`, `EnumClipboardFormats`, and `GetPriorityClipboardFormat` offer reconnaissance into what’s present and usable, helping tailor the next actions. Clipboard viewers can be registered via `SetClipboardViewer` or `AddClipboardFormatListener`, creating passive taps on clipboard changes without active polling. Individually, these APIs seem harmless, and just for interoperability and user convenience. But when leveraged together, they provide a low friction channel for theft, misdirection, and silent payload delivery, all without touching disk or raising noise.

## 📚 Resources
- [Microsoft Docs: SetClipboardData](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setclipboarddata)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!