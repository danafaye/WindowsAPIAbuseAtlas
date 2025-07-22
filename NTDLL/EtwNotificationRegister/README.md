# 🎯 EtwNotificationRegister: Context Aware Stealth

## 🚀 Executive Summary
`EtwNotificationRegister` empowers malware with stealthy, real-time awareness of defensive telemetry activation, transforming passive observability into an active tripwire. By silently detecting when ETW providers, especially those tied to EDRs and sandboxing tools come online attackers gain the power to delay, alter, or abort malicious activity before detection can occur. This low noise surveillance enables evasive behaviors that frustrate runtime analysis and automated defenses alike, raising the bar for defenders who must now detect not just malicious actions, but the very signals malware listens for. Mastery of this API marks a subtle but significant shift from blunt force evasion to intelligent, context aware stealth in modern attacks.

## 🔍 What is EtwNotificationRegister?
`EtwNotificationRegister` wires up a callback to the Windows event tracing pipeline, giving tools a way to passively listen for ETW provider activity as it happens. It’s built for speed and efficiency, so no polling and no delays. It is just a clean hook into provider lifecycle changes, session state, and system trace metadata. Telemetry agents, profilers, and diagnostics frameworks use it to stay in sync with what's being instrumented, reacting in real time to shifts in execution context. Register once, get pinged when something moves—that’s the promise. For anything that needs to ride the heartbeat of ETW without getting in its way, this API is how you listen in.

## 🚩 Why It Matters
`EtwNotificationRegister` offers a quiet foothold into the ETW subsystem, allowing user-mode code to monitor the registration and lifecycle of event providers in real time. By wiring up a callback, it becomes possible to observe when new telemetry sources come online, when tracing sessions shift, or when instrumentation begins or ends. This passive visibility; without needing to emit or consume actual event payloads, makes it ideal for tracking system introspection from the sidelines. In the right hands, it’s used to build observability. In the wrong ones, it’s a tripwire for knowing when someone else is watching.

## 🧬 How Attackers Abuse It
In adversarial hands, `EtwNotificationRegister` becomes a tripwire. Instead of consuming telemetry, malware wires up a callback to detect when someone else turns it on. By registering for `EtwNotificationTypeProviderEnabled` or `EtwNotificationTypeGuid` events, malware can silently monitor the moment a tracing provider is registered (like those used by EDRs, logging frameworks, or dynamic analysis sandboxes). This way, the callback doesn’t need to parse event contents or touch payload data; it simply watches for motion on the telemetry line.

This setup gives malware runtime awareness without API noise: no `EtwEventWrite`, no `OpenTrace`, no event consumption, just passive surveillance. If a known defensive provider registers (like Microsoft Windows Threat Intelligence or Sysmon), the callback can trigger conditional logic: stop execution, disable advanced features, or exit entirely. In some payloads, this registration is pushed to a separate thread or obfuscated with dynamic imports, making it harder to trace during static analysis. And because this API doesn’t require elevation or special privileges, even commodity malware can use it to sense when it's being watched. It’s ETW-aware execution, designed to hide when the lights come on. 🪳

## 🛡️ Detection Opportunities

Here are some sample YARA rules to detect suspicious use of `EtwNotificationRegister`:

See [EtwNotificationRegister.yar](./EtwNotificationRegister.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - **Unusual Registration for ETW Provider Notifications**: Code that calls `EtwNotificationRegister`, especially outside of debuggers or telemetry agents, is rare. When seen in loaders, post-exploitation tools, or commodity malware, it strongly suggests environmental awareness logic.
 - **Callback Registered Without Event Consumption**: No calls to `OpenTrace`, `StartTrace`, or `EtwEventWrite`, but a `EtwNotificationRegister` with a live callback? That’s a red flag. This pattern indicates interest in when ETW activates, not in the data it emits.
 - **Trigger on Specific Provider GUIDs**: Some malware watches for the registration of known defensive providers like Microsoft Windows Threat Intelligence, Microsoft Windows Security Auditing, or Sysmon. Callbacks wired to these GUIDs may trigger conditional logic to halt execution or pivot behavior.
 - **Process Halts or Alters Flow Post-Notification**: Behavioral shifts like thread termination, long sleep loops, or decryption logic skipping execution—shortly after an ETW notification fires suggest the callback is being used for sandbox or EDR detection.
 - **Thread Dedicated to Notification Handling**: In some payloads, a background thread is created solely to call `EtwNotificationRegister` and wait. This decouples telemetry awareness from main payload logic and can serve as an early-exit controller.
 - **Dynamic Resolution of EtwNotificationRegister or EtwSetNotificationCallback**: Use of `GetProcAddress` or hashed string resolution to load `EtwNotificationRegister` or `ntdll!EtwSetNotificationCallback` may indicate an attempt to evade static analysis or import address table based detections.
 - **No Corresponding Use of ETW Logging or Session Management APIs**: Legitimate ETW consumers typically call `StartTrace`, `EnableTrace`, or `ProcessTrace` in proximity. Their absence around a registration call is suspicious—especially if there's no real diagnostic or profiling context.
 - **Seen in Malware Running Under Explorer or WerFault Context**: Payloads that run in trusted parent processes but immediately register for ETW notification callbacks are often trying to time their behavior based on defender observability coming online.
 - **Callback Used to Modify Behavior In-Memory**: Some advanced malware uses the callback not just to exit, but to patch memory, suspend threads, or wipe in-memory payloads once ETW is detected. Look for tight follow-ups like `VirtualProtect`, `NtSuspendThread`, or `RtlZeroMemory`.

## 🦠 Malware & Threat Actors Documented Abusing EtwNotificationRegister
These technique don’t show up in every commodity loader, but when it does, it’s usually part of something stealthier. ETW notification abuse has been observed in advanced red team frameworks, obfuscated droppers, and evasive loaders designed to adapt at runtime. Malware families focused on sandbox evasion, EDR awareness, or staged payload delivery; those operating under high scrutiny use this API to stay quiet until the coast is clear. Think loader stage implants, APT tooling, and anything that wants to blend in until the moment it doesn’t.

### **Ransomware**
 - CrossLock

### **Commodity Loaders & RATs**
 - Kovter
 - PlugX
 - ShadowPad

### **APT & Threat Actor Toolkits**
 - APT41
 - Lazarus
 - Equation Group

### **Red Team & Open Source Tools**
 - GhostPack (SharpGhost)
 - Metasploit
 - Sliver

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `EtwNotificationRegister`.

## 🧵 `EtwNotificationRegister` and Friends
`EtwNotificationRegister` rarely works alone. It's part of a family of ETW APIs that attackers and defenders alike use to navigate the telemetry landscape. Functions like [EtwEventWrite](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/NTDLL/EtwEventWrite) and `EtwEventWriteTransfer` handle event logging, while `EtwSetInformation` and `EtwGetTraceLoggerHandle` manage session control and tracing context. Malware often pairs `EtwNotificationRegister` with `EtwUnregister` to clean up hooks silently, or with `NtTraceControl` to manipulate trace sessions directly. For broader reconnaissance, adversaries combine it with `OpenTrace` and `ProcessTrace` to consume event streams or query live trace status. Together, this cluster forms a telemetry toolkit, either for deep observability or stealthy evasion, depending on who’s calling and why. Recognizing the dance of these APIs in close succession helps analysts distinguish legitimate diagnostics from malicious telemetry manipulation.

## 📚 Resources
- [Geoff Chappell: EtwNotificationRegister](https://www.geoffchappell.com/studies/windows/win32/ntdll/api/etw/evntapi/notificationregister.htm)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!