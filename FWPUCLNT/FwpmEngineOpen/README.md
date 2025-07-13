# 🧰 FwpmEngineOpen: Precision Network Control

## 🚀 Executive Summary
`FwpmEngineOpen` is the high-privilege handshake that opens the door to Windows' deepest network plumbing. It’s not a common sight in the wild, but when it appears, it signals intent to interact directly with the Windows Filtering Platform, one of the most powerful and fine-grained network control systems on the OS. While defenders often focus on higher-level APIs or command-line utilities, this function sits closer to the metal, giving attackers the ability to invisibly manipulate packet flow, suppress telemetry, or interfere with security tooling. Its presence alone may not be malicious, but its misuse is quiet, deliberate, and almost always means someone is reaching below the surface to reshape what packets live or die.

## 🔍 What is FwpmEngineOpen?
`FwpmEngineOpen` is the first handshake with the **Windows Filtering Platform (WFP)**, a powerful kernel-mode network inspection framework introduced in Windows Vista. WFP enables both Microsoft and third-party developers to interact with the networking stack for filtering, inspection, and modification of packet flow. When used legitimately, `FwpmEngineOpen` establishes a session with the filtering engine so that administrators, firewalls, or network security tools can register custom filters, sublayers, and callouts through other `Fwpm* APIs`. This allows applications to block ports, inspect traffic, or enforce policy based on conditions like IP ranges or protocol types. In normal operation, it’s a cornerstone of user-mode access to firewall and packet processing features; when this function shows up in the wild, it’s either configuring the rules or rewriting them entirely.

## 🚩 Why It Matters
For defenders, knowing `FwpmEngineOpen` is more than trivia. It’s table stakes for understanding how network controls work under the hood in Windows. This API is the gateway to the Windows Filtering Platform, the same system that enforces firewall rules, controls IPsec, and mediates packet flow for everything from system services to EDR agents. Any application, driver, or tool that touches Windows network policy, whether it's enforcing, logging, or inspecting. It often starts by calling `FwpmEngineOpen`. If you're monitoring endpoint behavior, building detections, or just trying to baseline what "normal" looks like on the wire, this API is a key signal that something is trying to talk to the network stack in a meaningful way.

## 🧬 How Attackers Abuse It
When attackers lean on `FwpmEngineOpen`, they’re stepping through the front door of the **Windows Filtering Platform** to twist network traffic to their advantage. By opening a session with the filtering engine, malicious code can register stealthy filters or callouts that hide their command-and-control channels, block defensive tools’ traffic, or reroute data to evade detection. This API becomes the pivot point for implanting hooks deep in the network stack. It enables malware to manipulate packets before security software even sees them. Understanding how adversaries abuse `FwpmEngineOpen` reveals how seemingly legitimate network management calls can be weaponized to cloak malicious communications in plain sight.

## 🛡️ Detection Opportunities
Here are some sample YARA rules to detect suspicious use of `FwpmEngineOpen`:

See [FwpmEngineOpen.yar](./FwpmEngineOpen.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
`FwpmEngineOpen` by itself won’t trip alarms, but defenders can catch its abuse by tuning in to *who’s calling it*, when, and why. Legitimate use is usually tied to known services like firewalls, VPN clients, or security platforms. When unknown or unsigned binaries initiate sessions with the WFP engine, especially outside of install or boot sequences, that’s a red flag. Pairing telemetry from API call traces, ETW providers (Microsoft-Windows-WFP), or Sysmon process activity with the presence of follow-on calls like `FwpmFilterAdd` or `FwpmCalloutAdd` can surface unauthorized filtering logic being injected into the stack. Filter rules that block connections to security vendor domains, redirect traffic, or hide outbound C2 should be treated as suspicious by default. The key is to baseline trusted sources and monitor for deviations—malicious use of FwpmEngineOpen always starts quiet, but it doesn’t stay that way for long.

## 🦠 Malware & Threat Actors Documented Abusing FwpmEngineOpen
`FwpmEngineOpen` is unusually scarce in malware not because it lacks power, but because it demands precision. Abusing the Windows Filtering Platform means interacting with a *well-guarded, verbose subsystem that screams forensics*. It requires administrative privileges, a deep grasp of network stack layering, and careful sequencing of `Fwpm*` calls. Each of which leaves telemetry breadcrumbs. For most threat actors, it’s overkill. Easier wins lie in `netsh`, registry tweaks, or proxy configs. The risk-to-reward ratio keeps `FwpmEngineOpen` relegated to red team implants and one-off post-exploitation experiments, not widespread in-the-wild tooling.

### **Commodity Loaders & RATs**
Snake Rootkit/RAT

### **Red Team & Open Source Tools**
Cobalt Strike

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `FwpmEngineOpen` for stealth and evasion.

## 🧵 `FwpmEngineOpen` and Friends
`FwpmEngineOpen` is the gateway to the "WFP stack", but it rarely works alone. It typically shows up alongside `FwpmSubLayerAdd`, `FwpmFilterAdd`, `FwpmCalloutAdd`, and `FwpmEngineClose`: a full chain used to register and activate custom filtering logic. For simpler or legacy manipulation, malware may instead lean on `SetWindowsFirewallSetting`, `INetFwPolicy2` COM interfaces, or shell out to `netsh advfirewall` for rule changes without touching `WFP` directly. Low-effort attackers bypass all of this via `RegAddKey` on firewall policy keys or by disabling services outright. But for those who do reach into `WFP`, `Fwpm* APIs` give fine-grained control—dropping, re-routing, or inspecting traffic at multiple stack layers, with surgical precision.

## 📚 Resources
- [Microsoft Docs: FwpmEngineOpen](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!