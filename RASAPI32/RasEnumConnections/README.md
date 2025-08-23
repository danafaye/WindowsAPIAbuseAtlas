# 🔗 RasEnumConnections

## 🚀 Executive Summary
`RasEnumConnections` might sound like one of those APIs you’d never need to worry about unless you were debugging a VPN client from the early 2000s. But here’s the thing: attackers don’t just go after the obvious APIs like `NtReadVirtualMemory` or `CreateRemoteThread`. Sometimes the quieter ones like `RasEnumConnections` are the most useful. This function gives visibility into what remote access (RAS) connections are currently active, which can help attackers orient themselves in a victim’s network environment.

## 🔍 What is RasEnumConnections?
At its core, `RasEnumConnections` enumerates active RAS connections; things like dial-up (yep, very rare, but it's sometimes the only viable option), VPNs, or other remote sessions. The call returns handles and connection data that let a program know what tunnels or links are in place. It’s not something most modern applications lean on every day, but it’s still in the API surface, and still works.

## 🚩 Why It Matters
From a defender’s perspective, knowing an attacker can easily ask Windows “what tunnels are open right now?” is a little unsettling. VPNs and remote access links are prime real estate. If malware can discover them, it can start piggybacking sessions, hijacking authentication, or just using that knowledge to plan lateral movement. In short, `RasEnumConnections` isn’t flashy, but it’s a neat little recon trick for adversaries.

## 🧬 How Attackers Abuse It
Attackers don’t need to reinvent the wheel. By calling `RasEnumConnections`, malware can instantly list out active VPNs and remote links, no noisy registry scraping or network sniffing required. Once they have that intel, they can decide if there’s a juicy VPN session to abuse, or simply use the information to target credentials stored by the VPN client. This API can also be chained with others (like `RasGetEntryProperties` or even LSASS dumping) to get a much fuller picture of how remote connectivity is configured. Think of it as a quick map check before the real work begins.

## 🛡️ Detection Opportunities
If you’re watching for odd use of RAS APIs on endpoints, `RasEnumConnections` is one to keep an eye on. It tends to stick out in modern environments since legitimate use cases are pretty rare outside of VPN clients or legacy apps. Pairing monitoring of this API with process context, what executable is calling it, what commandline args it has, whether it’s signed can help filter noise and raise the right alerts.

Here are some sample YARA rules to detect suspicious use of `RasEnumConnections`:

See [RasEnumConnections.yar](./RasEnumConnections.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - **Unexpected imports of rasapi32.dll**: Most modern enterprise software doesn’t touch RAS APIs. If you see a random binary or script pulling in rasapi32.dll, it’s worth asking why.
 - **Office documents or macros making RAS calls**: That’s almost never legitimate. If Word, Excel, or PowerPoint are suddenly poking around remote access connections, it’s a strong red flag.
 - **Scripting engines like wscript, cscript, or PowerShell invoking RAS APIs**: These tools are flexible but shouldn’t be sniffing out VPN connections. That behavior often points to loader or recon activity.
 - **Custom loaders and commodity malware calling `RasEnumConnections` during early execution**: Attackers often want a quick lay of the land before moving on to credential theft or lateral movement.
 - **API use correlated with credential access attempts**: On its own, `RasEnumConnections` is just reconnaissance. But if it shows up alongside LSASS dumping, DPAPI abuse, or registry reads of VPN client settings, the intent becomes much clearer.
 - **Enumeration followed by network mapping or lateral movement**: Attackers who identify active tunnels may pivot through them, using the victim’s VPN session as a shortcut deeper into the environment.

## 🦠 Malware & Threat Actors Documented Abusing RasEnumConnections

### **Ransomware**
- Conti
- Royal

### **Commodity Loaders & RATs**
- Emotet
- Trickbot

### **APT & Threat Actor Toolkits**
- APT28 / FancyBear
- APT32
- APT41 

### **Red Team & Open Source Tools**
- CobaltStrike
- Nirsoft (dialuppass.exe)

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `RasEnumConnections`.

## 🧵 `RasEnumConnections` and Friends
`RasEnumConnections` rarely travels alone. Its closest friends are functions like `RasGetEntryDialParams` and `RasGetEntryProperties`, which attackers can use to dig deeper once they’ve enumerated what sessions exist. It’s also often paired with credential theft techniques. After all, finding the tunnel is only half the job; stealing the keys to it is the other half.

## 📚 Resources
- [Microsoft Docs: RasEnumConnections](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasenumconnectionsa)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!