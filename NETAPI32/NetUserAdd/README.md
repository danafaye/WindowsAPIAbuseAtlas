### 🔒 NetUserAdd  
### 🚀 Executive Summary  
User creation is one of the most fundamental post-exploitation actions, and `NetUserAdd` lets attackers do it cleanly, quietly, and without shelling out to noisy system tools. It’s been around forever, blends into legitimate admin activity, and doesn’t raise eyebrows unless you’re looking closely. Whether it’s ransomware establishing backup access or an APT laying down long-term persistence, this API shows up more than you might think, and it rarely sets off alarms.

### 🔍 What is NetUserAdd?  
`NetUserAdd` lives in `netapi32.dll` and lets code create new local user accounts on a Windows system. Give it the right structure and a few details, like a username and password, and it drops the account straight into the SAM database, no clicks required. It’s part of the old-school NetAPI set, **works over SMB**, and doesn’t need the user to be local. All it takes is the right privileges and a well-formed call.

### 🚩 Why It Matters  
`NetUserAdd` cuts straight to one of the core pillars of security: identity. For red teamers, it’s a quiet, native way to drop a user onto a box, no LOLBins, no extra tooling. For blue teamers, that means it can slip past detections that focus on command-line behavior or user-driven actions. It’s old, trusted, and still fully functional, which makes it perfect for abuse. If you’re not watching for it, someone could be creating high-privilege accounts right under your nose.

### 🧬 How Attackers Abuse It  
Attackers use `NetUserAdd` to silently create local accounts—often with administrative privileges, without firing off noisy command-line tools like `net.exe`. It’s a clean API call that does all the heavy lifting: username, password, group membership, and more. Once the account is in place, it can be used for persistence, lateral movement, or fallback access. Combine it with `NetLocalGroupAddMembers`, and you’ve got a stealthy, high-privilege foothold that might never show up in the usual logs. No prompt, no popup—just a new user, ready to go.

### 🛡️ Detection Opportunities  

### 🔹 YARA
Check out some sample YARA rules here: [NetUserAdd.yar](./NetUserAdd.yar).

> **Heads up:** These rules are loosely scoped and designed for hunting and research. They're **not** meant for production detection systems that require low false positives. Please test and adjust them in your environment.

### 🔸 Behavioral Indicators
`NetUserAdd` doesn’t leave the same breadcrumbs as command-line tooling, but it’s not invisible either. Look for user account creation events like `Event ID 4720` (a user account was created), especially if there's no corresponding `net.exe` or PowerShell activity tied to it. Track API usage from unexpected processes, malware often calls this from payloads that have no business managing users. Correlate with privilege escalation, remote logins, or sudden group membership changes. And if you’re seeing accounts pop up outside of standard provisioning flows? Time to dig deeper.

### 🦠 Malware & Threat Actors Documented Abusing NetUserAdd

For the latest technical write-ups, search for the malware or tool name together with "NetUserAdd" on reputable security blogs, threat intelligence portals, or simply google. (Direct links are not included to reduce maintenance.)

### Ransomware
 - Black Basta
 - Cuba
 - El Paco

### Commodity Loaders & RATs
 - AZORult++
 - Gh0stRAT
 - WarZoneRAT

### APT & Threat Actor Toolkits
 - Fin7
 - Indra

### Red Team & Open Source Tools
 - Cobalt Strike
 - Offensive AutoIt 
 - Red-Teaming-Toolkit

## 🧵 `NetUserAdd` and Friends
`NetUserAdd` rarely flies solo. It often shows up alongside `NetLocalGroupAddMembers`, which takes that newly created user and drops them into privileged groups like Administrators, stealthy privilege escalation in one neat call. `NetUserSetInfo` is another close cousin, letting attackers modify user details post-creation: rename accounts, reset passwords, or flip flags. And if you’re seeing `NetUserDel`? That’s the cleanup crew, often used to wipe traces after access. These `NetAPI` calls are old but reliable, and when used together, they form a low-noise, high-impact trifecta for persistence, escalation, and evasion. Keep an eye on them; they still get the job done.

## 📚 Resources
MITRE: [Natice API](https://attack.mitre.org/techniques/T1106/)
[Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas) (more like this)

> **Know of more?**  
> Open a PR or issue to help keep this list up to date!
