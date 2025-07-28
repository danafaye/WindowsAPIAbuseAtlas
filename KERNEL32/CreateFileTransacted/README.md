# 💾 CreateFileTransacted: Old School Stealth

## 🚀 Executive Summary
`CreateFileTransacted` enables file operations within a transactional context, letting malware write, modify, or stage files that can be rolled back, leaving little trace if interrupted or detected. Though deprecated and less common today, it’s a stealthy tool for sandbox evasion, timestomping, and covert payload staging. Awareness of its presence in telemetry is key, as its misuse signals advanced evasion tactics aiming to rewrite history on disk.

## 🔍 What is CreateFileTransacted?
`CreateFileTransacted` lets you open or create a file as part of a transaction, meaning the changes you make won’t be committed to disk until the transaction is explicitly finalized. It’s like having a safety net while doing file operations: write, edit, delete.  And, if something goes wrong, you can just roll the whole thing back like it never happened. This makes it handy for apps that need to ensure consistency across multiple file changes, especially when paired with the broader Transactional NTFS framework. The file handle it returns works just like the one from `CreateFile`, but it's bound to the transactional context you give it.

## 🚩 Why It Matters
`CreateFileTransacted` slips under the radar by design. It blends in, looks normal, and plays by the rules of the file system, just with an added layer of plausible deniability. When operations can be quietly tested, reversed, or staged without ever committing to disk, it becomes harder to pin down what actually happened and when. That kind of ambiguity is gold for anyone looking to manipulate the timeline of events or muddy forensic waters. It's not flashy, but it's slippery, and that's exactly the point.

## 🧬 How Attackers Abuse It
In a malicious context, `CreateFileTransacted` offers a low-noise way to stage payloads, manipulate files, or prep components for execution; all under the protection of a transaction. An attacker can write a file to disk, scan it, modify it, even sign it, all without those changes becoming visible until the transaction is committed. This transactional limbo makes detection harder: file I/O happens, but nothing lands permanently unless explicitly finalized. Combine it with `CommitTransaction` or `RollbackTransaction`, and malware gains precise control over what persists and when. Some techniques use this to test code execution safely or to delay payload deployment until just the right moment. And while *Transactional NTFS (TxF)* is deprecated, it's still available on many systems (including Windows 11), offering a stealthy, rarely watched lane for file ops with built-in erase-on-fail.

## 🛡️ Detection Opportunities

Here are some sample YARA rules to detect suspicious use of `CreateFileTransacted`:

See [CreateFileTransacted.yar](./CreateFileTransacted.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - **API call without legitimate context**: Most modern software doesn’t touch TxF, so when it shows up, it’s worth a second look.
 - **TxF used for payload staging**: Look for sequences where a transacted file is written to, read from, or mapped, especially if it’s executable content or DLLs. It’s classic tradecraft for staging code off the radar until it’s ready to go.
 - **Suspicious pairing with CommitTransaction**: Creation is one thing, but committing the transaction locks in the changes. A call to `CommitTransaction` immediately following file writes is often where the attacker flips the switch and makes it real.
 - **Avoidance of conventional file drop paths**: Malware might use transacted file creation in obscure directories or in places malware is known to drop (like C:\Windows\Temp, ProgramData, or even user profiles) where rollback and commit can happen quietly.
 - **No corresponding file visibility**: If ETW or Sysmon logs show file creation via TxF but the file never appears in a subsequent scan or file listing, that’s rollback in action. The attacker ran the op, got what they needed, and disappeared.
 - **Combo with hollowing or injection techniques**: `CreateFileTransacted` may be used to prepare a payload that’s never meant to run from disk. It’s loaded into memory, mapped, and injected somewhere else. Track for follow-on use of `MapViewOfFile`, `VirtualAlloc`, or [CreateRemoteThread](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/KERNEL32/CreateRemoteThread).
 - **Use by non-interactive or script-driven processes**:
When a script engine (wscript.exe, powershell.exe) or an unexpected process dips into TxF territory, assume you’re not watching a software installer. This API is rarely touched by normal scripts.
 - **Rare parent-child relationships**: If a child process is calling `CreateFileTransacted` and its parent isn’t an installer, backup tool, or known dev utility. Raise an eyebrow. TxF isn’t a go-to for everyday apps.
 - **Use after defense evasion activity**: If you see TxF usage after disabling logs, tampering with EDR hooks, or clearing Event Logs, that’s part of the cleanup. They’re staging or patching files in a way that lets them walk it back if needed.
 - **Low prevalence across fleet telemetry**: This one’s easy math: if you’ve got 10,000 endpoints and only three processes ever touch `CreateFileTransacted`, and one of them is running from `%APPDATA%\ChromeUpdate\chrome.exe`, you’ve got a problem.

## 🦠 Malware & Threat Actors Documented Abusing CreateFileTransacted
`CreateFileTransacted` shows up in malware that wants stealth with a side of rollback. It lets attackers interact with files inside a transactional context. This is useful for writing payloads, staging data, or dropping decoy artifacts. Then rolling it all back like it never happened. You’ll see it in sandbox evasion, timestomping, and loaders that use TxF to quietly prep payloads before committing (or not committing) the changes. It's not common, but when it shows up, it’s worth paying attention.

### **Ransomware**
 - Cerber
 - GandCrab 
 - Locky

### **Commodity Loaders & RATs**
 - DarkComet
 - Gh0st RAT
 - PlugX

### **APT & Threat Actor Toolkits**
 - APT29 (Cozy Bear)
 - FIN6
 - APT33 (Refiend Kitten)

### **Red Team & Open Source Tools**
 - Maybe old ones, but I couldn't find any

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `CreateFileTransacted`.

`CreateFileTransacted` and TxF were deprecated by Microsoft starting Windows 8, limiting their use. Malware authors tend to prefer more reliable or forward-compatible methods, so TxF usage is a specialty technique often found in older or very targeted malware.

## 🧵 `CreateFileTransacted` and Friends
Transactional NTFS and `CreateFileTransacted` still linger under the hood in Windows 11, but their rocky reliability and deprecated status have pushed most attackers to greener pastures. Modern operators ditch TxF for more predictable moves: carving out payload staging zones with `CreateFileMapping` and `MapViewOfFile`, injecting code using `WriteProcessMemory` or queuing APCs, and handling atomic file swaps with `MoveFileEx` plus sneaky timestomping via `SetFileInformationByHandle`. These APIs deliver stealth and stability without the headaches, which makes TxF a legacy footnote instead of a daily tool. If you spot TxF in the wild, it’s either old-school or someone’s really doubling down on stealth.

## 📚 Resources
- [Microsoft Docs: CreateFileTransacted](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfiletransacteda)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!