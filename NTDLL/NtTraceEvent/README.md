# 🧨 NtTraceEvent — The Silent Signal

## 🚀 Executive Summary
`NtTraceEvent` is what happens when malware skips the safety rails and goes straight for the core. It’s raw, low-level, and invisible to most logging tools that expect nice, clean API usage. While defenders are busy watching `EtwEventWrite`, attackers are using this syscall to inject garbage, spoof events, or cloak payloads beneath a fog of fake telemetry. It’s not about turning ETW off, it’s about weaponizing it. Most analysts don’t monitor it. Most EDRs don’t catch it. And that’s exactly why threat actors love it. If you're not hunting for `NtTraceEvent`, you're probably not seeing the whole picture.

## 🔍 What is NtTraceEvent?
At first glance, `NtTraceEvent` looks like background noise — just another cog in Windows' event tracing machinery (ETW). But don’t let that fool you. It’s the raw syscall that feeds trace data straight into the kernel, powering everything from performance counters to forensic telemetry. Think of it as the **bare-metal cousin of `EtwEventWrite`** same purpose, no training wheels. While `EtwEventWrite` is the friendly face you see in most apps, `NtTraceEvent` cuts out the middle layer and talks straight to the core. 

Legit use? Mostly system components and a handful of performance-heavy apps. You’ll almost never see it in userland. So when you *do*, it’s probably not just logging CPU temps.

> 💡 Want the higher-level overview of this technique? Check out the [EtwEventWrite entry](../EtwEventWrite/) first — this one dives deeper into the syscall underbelly.

### 🛰️ Common ETW Consumers
- Performance tools like **Perfmon**, **WPR**, and **WPA**
- **Sysmon**, **EDRs**, and other telemetry-hungry tools  
- **WMI** providers piggybacking on ETW data  
- Custom app logging (e.g., **SQL Server**, **IIS**, **.NET runtime**)  
- Internal Windows subsystems doing diagnostics under the hood

## 🚩 Why It Matters
`NtTraceEvent` isn’t just obscure, it’s sneeky and quiet. It bypasses all the typical ETW logging APIs and goes straight to the source. That makes it gold for malware authors and red teamers looking to jam ETW, spoof events, or confuse defenders. It shows up in ETW patching stubs, anti-monitoring frameworks, and obfuscated loaders trying to blind EDRs.

If you're looking for sneaky behavior that lives just beneath the logging surface, this is it. Most tools don’t watch for it. Most analysts don’t know it. But attackers? They love it.

## 🧬 How Attackers Abuse It
Attackers abuse `NtTraceEvent` in two major ways:

 - **ETW Takedown** – Shellcode or early-stage loaders will patch ETW functions like [EtwEventWrite](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/NTDLL/EtwEventWrite), then optionally call `NtTraceEvent` to throw junk events or confuse parsers. Some just call it with malformed data to trip up trace sessions or crash monitoring.
 - **Minimalist Logging** – Red teams love it for ultra-minimal telemetry. A few malware families use it to emit “fake” or misleading traces under fake provider GUIDs, just to clutter or mislead defenders watching ETW. It’s subtle, but in the right environment, it’s a great way to throw sand in the gears.

But here’s the thing: *almost nobody* ever calls NtTraceEvent directly. Most apps use higher-level wrappers like `EtwEventWrite`. So when this raw syscall shows up in isolation? That’s not normal.  To be safe look for both.

## 🧵 Sample Behavior
The chain usually starts with `GetModuleHandle("ntdll.dll")` or `LoadLibrary("ntdll.dll")`, followed by `GetProcAddress("NtTraceEvent")` or `GetProcAddress("EtwTraceEvent")` to grab the raw function. After that, it’s all about crafting a fake `EVENT_TRACE_HEADER + provider GUID` and jamming it in. In red team tooling, this shows up in malformed telemetry generators or in combo with `EtwRegisterTraceGuidsW` to spin up rogue providers on the fly.

The goal? Spam the telemetry pipeline with garbage, or worse, make your malware look like a trusted app by spoofing its trace signatures. You’re not disabling ETW. You’re corrupting it from within. It’s quieter than patching, subtler than blocking, and a nightmare for defenders trying to separate signal from noise.

** EVENT_TRACE_HEADER **
At the heart of abusing `NtTraceEvent` or `EtwTraceEvent` is this dirty little trick: you can craft your own `EVENT_TRACE_HEADER` structure, point it at some bogus payload, slap on a provider GUID, and make Windows log it like it came from a legit source.

Here’s the bare bones of how the malicious struct might look in memory:

```
EVENT_TRACE_HEADER header = {0};
header.Size = sizeof(EVENT_TRACE_HEADER) + payloadSize;
header.Flags = WNODE_FLAG_TRACED_GUID;
header.Class.Type = 0x0A;  // attacker-defined or spoofed
header.Guid = spoofedProviderGUID; // looks legit, isn't

// Optional payload follows this structure in memory
```
Then, the attacker calls 'EtwTraceEvent(traceHandle, &header, payloadSize, payload);`

ETW is built on trust. It assumes that if you’re calling `EtwTraceEvent` (and especially `NtTraceEvent`), you’re someone who should be calling it. There’s *no strict validation on the GUID or the payload content*. It just logs what you give it. That makes this a perfect tool for attackers to spam garbage telemetry, cloak their activity with spoofed provider IDs (like Microsoft-Windows-Security-Auditing), or even inject nonsense that breaks downstream analysis tools.

## 🛡️ Detection Opportunities
Legit software doesn’t hand-craft ETW trace events. If you see `NtTraceEvent` or `EtwTraceEvent` in the wild, especially in userland, pay attention. It’s not normal. Most well-behaved apps use higher-level wrappers like `TraceEvent` or `EventWrite`. Direct calls to `EtwTraceEvent` are rare and usually only found in deep system internals, performance profilers, or very specialized telemetry tools. Not in your random PDF reader.

### 🔸 Behavioral Indicators
-  User-mode processes resolving `NtTraceEvent` manually via `GetProcAddress("ntdll.dll", "NtTraceEvent")`. 
 - Unusual `EVENT_TRACE_HEADER` usage: short-lifetime headers, unknown provider GUIDs, or repetitive event types coming from non-standard processes. Like a custom GUID firing thousands of events in a second from a user process with no trace registration.
 - ETW provider spoofing: Look for GUIDs that match legit providers (like Microsoft-Windows-Security-Auditing) being used in unexpected processes, especially unsigned or low-reputation binaries.
 - Trace handles in suspicious hands: If malware calls `EtwRegisterTraceGuidsW`, it might be setting up a rogue trace session just to get a valid handle. Track processes registering custom providers and follow what they emit.
- Garbage event storms: Some attack chains intentionally flood the ETW pipeline with junk to overwhelm consumers or break logging. That might show up as spikes in EtwTraceEvent without a matching legitimate purpose.
 - Bonus tip: Cross-correlate memory allocation patterns. If you see `VirtualAlloc + shellcode-looking blobs` followed by `EtwTraceEvent` or `NtTraceEvent`, it may be masking real payloads inside fake event data.

### 🔹 YARA

Check out some sample YARA rules here: [NtTraceEvent.yar](./NtTraceEvent.yar).

> **Heads up:** These rules are loosely scoped and designed for hunting and research. They're **not** meant for production detection systems that require low false positives. Please test and adjust them in your environment.

## 🦠 Malware & Threat Actors Documented Abusing NtTraceEvent

### Ransomware
- BlackByte

### Commodity Loaders & RATs
- Beep Loader

### APT & Threat Actor Toolkits
- Tidrone
- Earth Ammit

### Red Team & Open Source Tools
- ScareCrow
- EDRSandblast
- Mimikatz (some variants)

> **Note:** This list isn't exhaustive. Many modern malware families and offensive security tools use `NtTraceEvent` for code injection and memory manipulation.

## 🧵 `NtTraceEvent` and Friends  
`NtTraceEvent` is just one gear in a larger telemetry machine. It’s part of the Event Tracing for Windows (ETW) core and works alongside a crew of APIs that push or shape the same stream of diagnostic data. `EtwEventWrite` is the big sibling, more common, more documented, and way more likely to show up in normal apps. Then there’s `EtwRegister`, `EtwSetInformation`, and `EtwWriteEx`, which define providers, set metadata, and structure event delivery. On the lower end, you’ve got `NtSetInformationTrace`, `NtQueryTrace`, and `NtStartTrace`, lesser-known syscalls that configure or manipulate tracing sessions directly. All of these touch the same telemetry nerve. Abuse any one of them, and you can hijack the logging stack, tamper with visibility, or straight-up fake event data. Different tools, same goal: distort the signal, break the trail, and make the bad stuff look normal.

## 📚 Resources
Great Example: [EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast)
GeoffChappell.com: [NtTraceEvent](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/traceapi/event/index.htm)
[Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas) (more like this)

> **Know of more?**  
> Open a PR or issue to help keep this list up to date!