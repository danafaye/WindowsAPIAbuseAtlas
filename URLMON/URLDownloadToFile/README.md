# 📥 URLDownloadToFile

## 🚀 Executive Summary
`URLDownloadToFile` is the small but handy Win32 API that lets a process reach out to an HTTP/HTTPS (and `file:`) URL and save what it finds to disk. It's a one line convenience for legitimate updaters, installers, and benign utilities, and a one line convenience for attackers who want to fetch payloads without the ceremony of WinINet/WinHTTP plumbing. Because it’s so simple, it shows up often in commodity malware, quick and dirty loaders, and scripted post exploitation activities. That simplicity is its power and also the reason defenders should watch it: a lone call to URLDownloadToFile is rarely malicious by itself, but combined with odd process ancestry, unusual download destinations, or defensive evasion behavior it’s a clear hunting signal.

## 🔍 What is URLDownloadToFile?
`URLDownloadToFile` is part of the URLMON (URL Moniker) API set and provides a synchronous, high level way to download a URL to a local file. The caller hands the API a URL, a path on disk, and optionally a callback interface. The function handles the HTTP request, follows redirects, negotiates basic auth if available, and writes the response to the requested file path. It’s blocking (the calling thread waits), it uses the URL moniker infrastructure under the hood, and because it’s part of usermode Win32, and it doesn’t require lower level HTTP code from the caller.

From a developer’s point of view it’s magical glue: "I need file X from http://example.com, here’s the path; go get it." From an attacker’s point of view it’s a fast way to persistently fetch components, stage payloads, or bootstrap execution without scripting the more verbose WinHTTP or PowerShell commands.

## 🚩 Why It Matters
This API is significant because of the gap between how often it’s used in legitimate software and how attractive it is to attackers. Installers and updaters may call it every day on your endpoints, but those same mechanics make it a fantastic one liner for malware. That duality means defenders need to pay attention to where, when, and by whom the call is made.

The danger isn’t the function itself but what happens around it. A legitimate installer may download signed binaries to Program Files, while a malicious stager might pull an unsigned payload into a temp folder and immediately run it. That’s where context becomes king.

## 🧬 How Attackers Abuse It
Attackers abuse `URLDownloadToFile` most commonly in lightweight stagers and droppers. A malicious Word macro, for example, doesn’t need to include a full network client. It can just call the API to pull down its second stage executable. Likewise, small downloaders use it to refresh themselves periodically, grabbing updated payloads or configuration files from attacker infrastructure.

Another trick is pairing `URLDownloadToFile` with built in execution mechanisms. After downloading a DLL, the malware might invoke `rundll32` to run it. Or after fetching an EXE, it could create a scheduled task to guarantee execution. In these cases the API is just the first domino: it gets the file, but what comes after is where the damage is done.

Attackers also sometimes hide the usage in unexpected processes. If a process like `dllhost.exe` or `msiexec.exe` (usually trusted and boring) starts calling this API, it muddies the waters. Suddenly, a very normal process is being used as a fetcher for malicious code, making the activity harder to separate from noise.

## 🛡️ Detection Opportunities
From a defender’s perspective, `URLDownloadToFile` is less about the call itself and more about everything surrounding it. You can hunt statically by looking for binaries that import the function directly, or dynamically by monitoring EDR telemetry for processes making the call. But the higher fidelity detections come from correlations.

If the API is called, where did the file land? Was it in a temp directory or tucked inside Program Files? Did the process immediately try to execute the freshly downloaded file? Was the parent process something mundane like Word or Explorer, where network downloads are unusual? All of these are context clues that turn a bland API call into a flashing red light.

Another angle is correlating the API call with network telemetry. If you can tie the download request to domains that are brand new, rapidly changing, or otherwise sketchy, you can raise the confidence even higher. Finally, it’s useful to build baselines. If a process has never once downloaded anything before, and now suddenly it does, that deviation alone is suspicious.

Here are some sample YARA rules to detect suspicious use of `URLDownloadToFile`:

See [URLDownloadToFile.yar](./URLDownloadToFile.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - A process that rarely or never performs network activity calling `URLDownloadToFile` (deviation from baseline).
 - Download target paths in temporary folders or user profile locations followed within seconds by execution (like `CreateProcess`, `rundll32.exe`, or side-loading via `regsvr32.exe`).
 - Parent/child process relationships that don't make sense: `explorer.exe` spawning `mshta` or word → macro → small EXE that calls `URLDownloadToFile`.
 - Repeated, scheduled, or periodic downloads from the same process, especially when paired with persistence mechanisms (Scheduled Tasks, Services).
 - Use of `URLDownloadToFile` from contexts that typically don’t need internet access (domain controllers, build servers, service accounts).
 - Downloads coming from short-lived domains, redirectors, or CDN endpoints that resolve to shifting IPs.
 - Post-download behavior consistent with staging: changing file attributes, deleting the original downloader, or moving the file to Program Files or other uncommon locations before execution.

## 🦠 Malware & Threat Actors Documented Abusing URLDownloadToFile

### **Ransomware**
 - EKing (Phobos)
 - REvil

### **Commodity Loaders & RATs**
 - QuantLoader
 - Remcos RAT

### **APT & Threat Actor Toolkits**
 - Bitter
 - Gamaredon

### **Red Team & Open Source Tools**
 - Most of them
 - Cobalt Strike
 - Metasploit

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `URLDownloadToFile`.

## 🧵 `URLDownloadToFile` and Friends
This API has plenty of cousins. `URLDownloadToCacheFile` works almost the same way but writes to the cache instead of an arbitrary file path. `WinINet` functions like `InternetOpen` and `InternetReadFile` give developers more control but at the cost of extra boilerplate. `WinHTTP` is often favored for automation and service contexts. Beyond APIs, attackers can achieve the same effect with scripting utilities like PowerShell (`Invoke-WebRequest`, `Invoke-RestMethod`) or LOLBins like `certutil` and `bitsadmin`. Each has its own quirks, but the theme is the same: Windows offers lots of ways to fetch a file, and attackers will pick the one that best balances stealth, reliability, and speed for their goals.

## 📚 Resources
- [Microsoft Docs: URLDownloadToFile](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775123(v=vs.85))
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!