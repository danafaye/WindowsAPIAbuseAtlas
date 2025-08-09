# 🛠️ ShellExecute: The Delegate 

## 🚀 Executive Summary
`ShellExecute` is the Windows equivalent of saying, “Hey shell, you deal with this.” Instead of manually spinning up processes with `CreateProcess`, you can hand `ShellExecute` a file, URL, or even a protocol, and it figures out how to open it using whatever handler is registered. That could mean launching a program, opening a document in Word, firing up the browser, or even running something with elevated privileges if you ask nicely with `runas`.

Attackers love it because it’s high level and indirect. The process you see in telemetry isn’t always the one that started the trouble. Defenders should pay attention because this indirection can hide a lot of malicious activity behind normal-looking user behavior.

## 🔍 What is ShellExecute?
`ShellExecute` and the more advanced `ShellExecuteEx` lives in `shell32.dll`. It takes parameters like `open`, `print`, `runas`, the target (file, URL, or special object), optional command line arguments, and a show mode for the window.

Once called, it hands the job to the shell, which looks up the appropriate handler in the registry and launches the right app or component. That might be `explorer.exe`, your default browser, Office, or even a COM object. This means the caller doesn’t have to care about the actual binary path and defenders might have to dig through a chain of processes to see what really happened.

## 🚩 Why It Matters
`ShellExecute` is dangerous in the wrong hands because it hands off execution to something else; often a trusted system process or registered handler. That hands off changes the story your telemetry tells. Instead of a suspicious binary running a payload, you might just see `explorer.exe` opening a browser or a builtin Windows utility. That misdirection makes incident response harder and can delay containment.

The API can also trigger actions through protocol handlers. Those are special URL schemes like `http:` or `mailto:` that tell Windows which program to use. While most are harmless conveniences, some (like `ms-msdt:` or `search-ms:`) can launch powerful builtin tools with attacker controlled parameters. Because these handlers are a normal part of the OS, defenders can’t just block them without breaking user workflows. This mix of trusted intermediaries and flexible triggers makes `ShellExecute` a natural choice for attackers who want to blend into normal user behavior while still executing malicious code.

## 🧬 How Attackers Abuse It
Attackers use `ShellExecute` as a flexible launchpad for whatever they want to run.

A common trick is passing it a malicious URL. The browser or another registered handler will download and run the payload, while security logs just see “user opened a web page.” That same hand off works with custom or abused protocol handlers for example, `ms-msdt:` can pop the Microsoft Support Diagnostic Tool, or `search-ms:` can launch Windows Search with an attacker controlled query that opens files from a remote share.

They also target files that Windows knows how to “open” automatically. `.LNK` (shortcut) and `.URL` (internet shortcut) files can point to remote payloads or commands. When `ShellExecute` is told to open them, Windows happily follows the pointer.

Finally, the `runas` verb lets attackers prompt for elevation. If the user clicks “Yes” in the UAC prompt, the payload now runs with admin rights. Because `ShellExecute` often launches things indirectly, the parent process in logs might be a trusted application instead of the real malicious source, which helps attackers hide in plain sight.

## 🛡️ Detection Opportunities
While `ShellExecute` itself is a legitimate and very common API, you can spot suspicious use by focusing on what it’s being asked to open and how it’s being called:

 - **Weird or risky verbs**: The runas verb is perfectly normal when used by installers or admin tools, but in the middle of a phishing chain or from a low-trust process, it’s suspicious. Logging command-line activity, process creation, and verb usage can help flag abuse.
 - **Odd file types**:  Look for .LNK, .URL, or .hta files being launched unexpectedly, especially if they came from temp directories, user downloads, or email caches.
 - **Protocol handler abuse**: Monitor for rare or unexpected custom URI schemes (like ms-msdt: or search-ms:) being opened, which can be chained into exploits.
 - **Unusual parent-child relationships**: If a non-browser process suddenly launches a browser to a suspicious site, or a document viewer launches PowerShell via ShellExecute, that’s worth a closer look.
 - **Endpoint telemetry**: EDR tools that capture API call stacks can help identify when ShellExecute is used as an indirect launcher, giving visibility into the original caller.

By combining these signals, you can separate the thousands of harmless ShellExecute calls from the few that could be part of an attack chain.

Here are some sample YARA rules to detect suspicious use of `ShellExecute`:

See [ShellExecute.yar](./ShellExecute.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - `explorer.exe` or an Office app spawning a LOLBin like `PowerShell` or `rundll32`.
 - `ShellExecute` launching a protocol handler shortly before suspicious network activity.
 - Use of `runas` followed by privilege escalation.

## 🦠 Malware & Threat Actors Documented Abusing ShellExecute

### **Ransomware**
 - Nefilim
 - Proton
 - Ryuk

### **Commodity Loaders & RATs**
 - AsyncRAT
 - Emotet
 - GrimAgent

### **APT & Threat Actor Toolkits**
 - APT 29
 - Charming Kitten
 - TA505

### **Red Team & Open Source Tools**
 - Cobalt Strike
 - Metasploit
 - Nishang

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `ShellExecute`.

## 🧵 `ShellExecute` and Friends
`ShellExecuteEx` is the more capable sibling, letting you grab a process handle or set extra flags. Under the hood, a `ShellExecute` call often leads to `CreateProcess` anyway, but the path taken is less obvious. It can also pull in COM objects, shell extensions, and various LOLBins depending on what handler is triggered.

## 📚 Resources
- [Microsoft Docs: ShellExecute](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecutea)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!