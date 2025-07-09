# 🕵️‍♂️ ZwQuerySystemInformationEx

## 🚀 Executive Summary
`ZwQuerySystemInformationEx` is one of those APIs that barely whispers when it’s used—but when it shows up, it speaks volumes. Undocumented, under-monitored, and rarely touched by standard software, it’s the kind of native syscall threat actors reach for when they want answers without leaving a trail. It quietly unlocks access to sensitive kernel structures, thread states, handle tables, and low-level process info—exactly the kind of telemetry malware needs for sandbox evasion, recon, and target profiling. Its rarity is its strength: defenders rarely log it, sandboxes rarely emulate it, and most EDRs don’t treat it as suspicious unless you’re already looking. That’s what makes it dangerous. If you see it, pay attention—this is not normal software behavior. This is tradecraft.

## 🔍 What is `ZwQuerySystemInformationEx` 
This is the quiet, undocumented native syscall that lets you tap into the Windows kernel for low-level system details, offering more precision than you’ll find in most user-facing APIs. It’s not in the Win32 docs, and you won’t see it in your average developer’s toolkit. But for those who know where to look, it’s a hidden gem, feeding internal components precise data about processes, handles, and system state. It’s selective, elusive, and if you know how to ask, it’ll tell you exactly what you need to know.

## 🚩 Why It Matters
Cyber professionals should know this one exists, not because it shows up often, but because when it does, it usually means someone knows exactly what they’re doing. `ZwQuerySystemInformationEx` lives below the usual detection surface, tucked away in undocumented corners where the normal rules don’t apply. It’s the kind of API you won’t catch in logs or training labs, but it’s out there, in custom tooling, proof-of-concepts, and threat actor kits built for quiet precision. While rare, its use often signals **stealthy reconnaissance or probing deep into the system’s secrets**, making it a favored tool for those wanting to fly under the radar. If you’ve never heard of it, that’s by design. But if you care about what slips past the radar, this one belongs on your map.

## 🧬 How Attackers Abuse It
`ZwQuerySystemInformationEx` is the spy for low-level system snooping, giving attackers a direct line to the kernel’s inner workings. Need to enumerate running processes and threads? Check. Want to peek into handle tables or open object lists to spot what’s hooked or hidden? Done. Curious about loaded kernel drivers or subtle artifacts that reveal virtualization or sandbox traps? It’s got you covered. From stealthy reconnaissance and environment detection to hunting defensive tools and mapping security posture, this API lets bad actors gather intel that’s invisible to most user-mode APIs and security hooks. Versatile, quiet, and dangerously under the radar `ZwQuerySystemInformationEx` packs a lot of punch in a single, undocumented call.

## 🛡️ Detection Opportunities
Because `ZwQuerySystemInformationEx` operates beneath the usual user-mode radar, spotting its misuse requires looking beyond typical API call logs. Here are the best angles:

 - **Monitor direct calls to ntdll.dll exports**: Many security tools focus on higher-level Win32 APIs, but suspicious or unexpected calls to `ZwQuerySystemInformationEx` in `ntdll.dll` especially from non-system processes—should raise eyebrows.

 - **Look for unusual parameter patterns**: Attackers often query specific, obscure system information classes or pass crafted parameters to extract hidden kernel objects, handles, or driver info. Detecting calls with uncommon or undocumented info class values is a strong signal.

 - **Correlate with low-level process reconnaissance**: Frequent or repeated queries to gather process/thread info combined with little other legitimate activity can indicate stealthy reconnaissance.

 - **Watch for chains including handle enumeration and object queries**: When `ZwQuerySystemInformationEx` calls are paired with functions like `NtQueryObject`, `NtOpenProcess`, or `NtDuplicateObject`, it suggests an attacker is mapping handles and processes in detail.

**Another general thing about these undocumented Windows APIs**

Attackers know `ZwQuerySystemInformationEx` isn’t in any official import tables, so they get crafty resolving its address at runtime. They often walk the export table of ntdll.dll manually, searching for the function by name, a dead giveaway if you’re monitoring suspicious export parsing. Others use dynamic `GetProcAddress` calls combined with string obfuscation or hashing to hide what they’re looking for. Detecting these tricks means watching for processes that perform unusually complex export enumeration or suspicious string decoding routines targeting ntdll.dll. Tracking calls that combine manual PE parsing with suspicious syscall invocation patterns can catch attackers trying to unlock this stealthy API’s power before they even call it.

## 🦠 Malware & Threat Actors Documented Abusing ZwQuerySystemInformationEx

### Ransomware
 - BlueSky
 - DragonForce
 - LockBit 4.0
 - MountLocker

### Commodity Loaders & RATs
 - Biopass RAT
 - PlugX
 - Remcos RAT
 - Upatre

### APT & Threat Actor Toolkits
 - APT29 (CozyBear)
 - Turla
 - Fin7
 - DarkHotel
 - Equation Group

### Red Team & Open Source Tools
 - BruteRatel
 - SharpHound (BloodHound)
 - Shellter 
 - Process Explorer

> **Note:** This list isn't exhaustive. Many modern malware families and offensive security tools could use `ZwQuerySystemInformationEx`.

## 🧵 `ZwQuerySystemInformationEx` and Friends
When it comes to peeling back Windows’ layers, `ZwQuerySystemInformationEx` isn’t the only player in the game, but it’s one of the stealthiest. Its relatives, like `NtQuerySystemInformation` and `ZwQuerySystemInformation`, offer similar access to system internals but with less finesse and more visibility. Higher-level APIs like `QuerySystemInformation` don’t officially exist, but their functional cousins `NtQueryInformationProcess`, `NtQueryObject`, and `NtQueryInformationThread`, help carve out more specific slices of system data. These calls often serve as wrappers or complementary tools, letting attackers and red teams gather process lists, thread info, handle tables, and object details. Together, this family of native syscalls provides a powerful toolkit for deep reconnaissance ... quietly digging through the kernel’s secrets while most defenses keep looking elsewhere.

## 📚 Resources
 - GeoffChappell.com: [ZwQuerySystemInformationEx](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/query.htm)
 - [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas) (more like this)

> **Know of more?**  
> Open a PR or issue to help keep this list up to date!