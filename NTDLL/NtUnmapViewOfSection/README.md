# 🗺️ NtUnmapViewOfSection: Wipe, Replace & Execute

## 🚀 Executive Summary
`NtUnmapViewOfSection` is the quiet prelude to loud trouble. A surgical API that clears memory space so malware can hijack execution under the radar. It's a favorite across ransomware crews, infostealers, APTs, and red teamers alike, showing up in everything from classic process hollowing to evasive memory loaders. Spotting it in the wild is like catching a magician just before the switch-a-roo; nothing has gone boom yet, but the payload’s already backstage. For defenders, it's a critical signal in the timeline of intrusion. Miss it, and you might miss the moment malware makes its move. Knowing how and when this API is used means knowing when something trusted is about to be turned into something very much not-trusted.

## 🔍 What is NtUnmapViewOfSection?
`NtUnmapViewOfSection` is the memory bouncer. Its job is to kick a mapped section out of a process’s address space. Legit tools use it when they need to clear the way, like loaders prepping for an update or debuggers making room for patched code. It’s not flashy, but it’s essential: one call, and that chunk of memory is gone, ready to be replaced with something new. When you see it in clean software, it’s usually just cleaning up or resetting the board ... nothing shady, just making space to do things right.

## 🚩 Why It Matters
If you work in cyber and you don’t know `NtUnmapViewOfSection`, you’re missing a key move in the playbook. This API shows up right before something big happens: swapping out memory, clearing the way for injected code, or setting the stage for a hijack. It’s the moment just before the magic trick, when the deck gets reshuffled. Whether you're hunting threats, building detections, or reverse engineering shady loaders, spotting this call is like catching the setup to the punchline. It doesn’t always mean trouble—but when it does, it’s usually the quiet before the storm.

## 💀 How Attackers Abuse It
`NtUnmapViewOfSection` is the cleanup crew in a classic shell game. Malware calls it when it wants to kick out a legit PE image from memory and slide something malicious into its place, often without breaking the illusion. It’s the setup move in process hollowing, module stomping, and payload replacement techniques where stealth is the name of the game.

 - **Process Hollowing**:  The most common abuse. Spawn a benign-looking process in a suspended state (think svchost.exe), then use `NtUnmapViewOfSection` to wipe its original image. That frees up the exact memory range where the malware can map its own payload using `NtAllocateVirtualMemory` or `NtMapViewOfSection`. Resume the thread, and boom! Now your malware is running in a signed, trusted-looking container.
 
 - **Module Stomping**: Instead of replacing an entire process, attackers use this API to target individual DLLs. By unmapping a loaded module (like ntdll.dll), they can write in custom shellcode while keeping the original module handle intact. This messes with memory scanners and signature-based detection, since the metadata looks legit but the bytes tell a different story.
 
 - **In-memory Patching & Loader Tricks**: Some custom loaders will map a PE file into memory, use it briefly, and then clean up traces by calling `NtUnmapViewOfSection`. Others unmap themselves entirely post-injection to reduce memory footprint and frustrate forensic tools. It's also used in staged implants that temporarily map second-stage payloads, execute, and then unmap to stay ephemeral.

 - **Sandbox & Hook Evasion**: Advanced malware may unmap system DLLs (like `kernel32.dll`) and remap "clean" versions from disk, evading userland API hooks planted by EDRs. `NtUnmapViewOfSection` makes this possible by removing the tainted or monitored memory region first, then restoring a pristine copy for stealthy operations.

 - **Hybrid Techniques**: Modern threats often chain `NtUnmapViewOfSection` with `NtCreateSection`, `NtMapViewOfSection`, and `NtWriteVirtualMemory` for multi-stage, fileless injection flows. It's a utility player in any malware framework that wants to swap code under the radar without leaving disk artifacts.

## 🛡️ Detection Opportunities

Here are some sample YARA rules to detect suspicious use of `NtUnmapViewOfSection`:

See [NtUnmapViewOfSection.yar](./NtUnmapViewOfSection.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
If you see `NtUnmapViewOfSection`, pay attention. It’s not inherently malicious, but it’s almost always a precursor to something sketchy when it shows up in untrusted binaries. It’s quiet, clean, and often the first move before malware makes itself at home.

## 🦠 Malware & Threat Actors Documented Abusing NtUnmapViewOfSection
`NtUnmapViewOfSection` is a staple across the entire threat landscape. From ransomware gangs and commodity malware to sophisticated APTs and crimeware operators. It’s a go-to move whenever stealthy code injection or process manipulation is needed. Whether in targeted attacks or mass campaigns, attackers rely on it to quietly wipe out legitimate memory sections and slip their payloads in without raising alarms. Red teams and open-source projects also lean on this API as a reliable, battle-tested technique to mimic adversary behavior and test defenses. Simply put, if it involves covert code replacement in memory, `NtUnmapViewOfSection` is almost always in the mix.

### **Ransomware**
- Babuk
- Lockbit
- TorrentLocker

### **Commodity Loaders & RATs**
- Bazar Trojan
- HijackLoader
- LummaStealer
- XLoader

### **APT & Threat Actor Toolkits**
 - APT33
 - OilRig
 - Winnti

### **Red Team & Open Source Tools**
 - Donut
 - Koadic
 - Metasploit
 - Sliver
 
> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `NtUnmapViewOfSection` for stealth and evasion.

## 🧵 `NtUnmapViewOfSection`, `ZwUnmapViewOfSection` and Friends
Whether it's `NtUnmapViewOfSection` or its nearly identical twin `ZwUnmapViewOfSection`, this API is almost never working alone. It’s just the first step in a well-rehearsed memory hijack. You’ll usually catch it side-by-side with `NtCreateSection` to define the payload, `NtMapViewOfSection` to lay it into memory, and `NtWriteVirtualMemory` to stitch in shellcode or a full PE image. From there, `SetThreadContext`, `NtResumeThread`, or `CreateRemoteThread` takes over to launch execution. The "Zw" variant might show up in custom loaders or shellcode where direct system call stubs are preferred, but the role stays the same: clear out legitimate memory so something more interesting can move in. If you’re tracking this call, widen the lens. It’s just one piece of a tightly choreographed injection chain that almost always means something sneaky is underway.

## 📚 Resources
- [Microsoft Docs: ZwUnmapViewOfSection](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwunmapviewofsection)
- [NTAPI Undocumented Functions](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FSECTION_INHERIT.html)
- [MITRE: Process Injection: Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!