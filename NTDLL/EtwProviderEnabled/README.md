# 👀 EtwProviderEnabled: Sneakpeek

## 🚀 Executive Summary
`EtwProviderEnabled` is a subtle but powerful function that reveals whether Windows Event Tracing for Windows (ETW) providers are actively monitoring system activity. From a defender’s standpoint, it’s a cornerstone for telemetry and threat detection. From an attacker’s perspective, it’s a stealth gatekeeper malware and red team tools use it to probe if ETW logging is enabled before executing suspicious or malicious actions. This API enables adversaries to tailor their behavior to avoid detection, making it a critical function for blue teams to understand and monitor. Recognizing the presence and misuse of `EtwProviderEnabled` calls can help defenders catch evasive malware and improve threat hunting effectiveness.

## 🔍 What is EtwProviderEnabled?
Before a program fires off trace events, it’s got to know is anyone even listening? That’s where `EtwProviderEnabled` comes in. This function checks if a specific ETW provider is currently active and whether the logging level and keyword mask match what’s enabled. It’s a performance win: rather than blindly generating events (and wasting cycles), apps can skip the work if no ETW session is interested. You’ll see this in action across Windows internals, drivers, and legit software that leans on ETW for diagnostics and telemetry.

## 🚩 Why It Matters
If you're defending Windows systems, you need to understand how attackers treat observability like a minefield. ETW is one of the few built-in mechanisms defenders can use to trace what malware is doing in real time. But if malware can check whether an ETW provider is active before making its move? That's a problem. `EtwProviderEnabled` gives attackers the ability to tiptoe around detection only executing malicious logic when they know logging isn't happening. Understanding this function helps blue teamers figure out when stealth is being prioritized over execution, and it helps red teamers test how noisy their tools really are.

## 🧬 How Attackers Abuse It
Here’s where things get sneaky. An attacker can call `EtwProviderEnabled` to query the status of common security relevant ETW providers like Microsoft Windows Threat Intelligence, Sysmon’s providers, or even their own custom ones if defenders are getting fancy. If the call returns false (meaning no one’s watching), the malware proceeds with injection, credential theft, or persistence setups. If it returns true, the code backs off or changes behavior. In other words, `EtwProviderEnabled` becomes a tripwire detector: malware uses it to probe for blue team surveillance before acting. It's a lightweight evasion trick, often missed in static analysis, and deadly effective in the right hands.

## 🛡️ Detection Opportunities
`EtwProviderEnabled` itself doesn’t scream malicious, but context is everything. Most legitimate use happens in well known binaries and libraries think drivers, telemetry agents, or monitoring tools. So when you spot this function being called by an unknown process, unsigned binary, or something running from an odd location (like %TEMP%, %APPDATA%, or a user profile directory), your spidey senses should tingle. Pair that with process ancestry was this thing spawned by a phishing doc, LOLBin, or PowerShell script? And you’ve got a story worth chasing. For deeper detection, EDRs that can trace API call flow should flag anomalous or out-of-place use of EtwProviderEnabled, especially if followed by behavior like injection, credential access, or process hollowing.

Here are some sample YARA rules to detect suspicious use of `EtwProviderEnabled`:

See [EtwProviderEnabled.yar](./EtwProviderEnabled.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
Look for this pattern: a process checks `EtwProviderEnabled`, then conditionally runs high risk behaviors only if ETW is disabled. It’s a logic bomb gated by surveillance. You might see it precede calls like `WriteProcessMemory`, `NtCreateThreadEx`, or `LsaRetrievePrivateData`, but only when logging is off. Some malware will also enumerate known ETW providers beforehand or zero out related structures (`EtwEventRegister`, `EtwpNotifyGuid`, others). Another flag: anti-analysis stalling tactics, if the binary sleeps, forks itself, or delays execution after calling `EtwProviderEnabled`, it’s likely waiting for sandbox timeouts or trying to time blue team instrumentation. Stack those tells, and you’ve got a behavioral fingerprint of stealthy, ETW aware malware.

## 🦠 Malware & Threat Actors Documented Abusing EtwProviderEnabled

### **Ransomware**
- LockBit
- Ryuk

### **Commodity Loaders & RATs**
- Dridex
- IcedID
- RustyBuer 

### **APT & Threat Actor Toolkits**
- APT10
- APT29
- APT41

### **Red Team & Open Source Tools**
- Cobalt Strike
- Mythic Framework
- Sliver

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `EtwProviderEnabled`.

## 🧵 `EtwProviderEnabled` and Friends
`EtwProviderEnabled` isn’t flying solo. There’s a whole little clique of ETW-aware functions that attackers can (and do) abuse for visibility checks and evasion. `EventRegister` and `EtwEventRegister` are used to hook into providers, and sometimes malware registers fake ones to spoof legitimacy or monitor system state. `EtwEventWrite` and `EtwWriteEx` are used to emit events, so if you see them conditionally gated by provider checks, you’re likely looking at instrumentation aware logic. Then there’s `NtTraceEvent` and `TraceEvent` down in the native layer, and even `ControlTrace` and `StartTrace` if the attacker is getting bold and trying to disable or enumerate sessions outright. Any time malware starts poking around the ETW subsystem without a good reason, it’s probably not just there to file a bug report.

## 📚 Resources
- [Microsoft Docs: EtwProviderEnabled](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-etwproviderenabled)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!