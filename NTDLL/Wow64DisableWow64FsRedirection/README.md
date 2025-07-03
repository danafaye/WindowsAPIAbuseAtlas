# Wow64DisableWow64FsRedirection

## 🚀 Executive Summary
`Wow64DisableWow64FsRedirection` is a sneaky backstage pass for 32-bit processes running on 64-bit Windows. It flips off the OS’s automatic file system detour, letting code write, read, or launch files straight from the real System32 folder instead of the redirected SysWOW64. This subtle toggle opens a stealthy door for malware to drop payloads where defenders least expect, dodge common detection hooks, and impersonate legit system activity. Because it’s quiet, built into the OS, and rarely needed outside installers, spotting its misuse can be a powerful early warning sign of deeper compromise.

## 🔍 What is `Wow64DisableWow64FsRedirection` 
Windows tries to be helpful: when a 32-bit process runs on a 64-bit system, it silently redirects file system access. Ask for `C:\Windows\System32`? You’ll get `C:\Windows\SysWOW64` instead. This keeps legacy stuff from breaking, but sometimes, a process really wants the real path—and that’s where `Wow64DisableWow64FsRedirection` steps in. Call it once, and the OS stops getting in the way. No more redirection. You get raw access to the actual 64-bit system files. It shows up in installers and setup scripts that know what they’re doing. Everyone else? They probably shouldn’t be touching it.

## 🚩 Why It Matters
Windows plays a quiet shell game with 32-bit processes: every time they reach for `System32`, the OS sneakily hands them `SysWOW64` instead. It’s meant to keep things compatible, but that redirection also becomes part of our detection assumptions. Most defenders, tools, and logs rely on it. Enter `Wow64DisableWow64FsRedirection`, and suddenly those assumptions fall apart. A 32-bit process can now access the real 64-bit file system, sidestep visibility, and do things that normally aren’t possible. It’s a low-noise way to quietly break the rules, and when it shows up outside an installer, it deserves attention.

## 🧬 How Attackers Abuse It
Let’s say you’ve got a 32-bit malware dropper running on a 64-bit machine. It wants to copy a payload into `C:\Windows\System32`. Sounds simple, right? Except… it’s not.

Windows steps in and says, “Hold up—you’re a 32-bit process. I’ll just redirect that to `C:\Windows\SysWOW64` instead.” That’s automatic. Invisible. Built into the OS. And it stops your payload from landing where you want it.

To solve this malware do? It calls `Wow64DisableWow64FsRedirection`. Boom—redirection is off. Now when it writes to `System32`, it actually hits `System32`. That means it can:

 - Drop a 64-bit DLL where a legit 64-bit process will load it
 - Bypass EDRs that only monitor WOW64 paths for 32-bit processes
 - Load system tools (like regsvr32.exe or rundll32.exe) from the real folder, not the 32-bit one
 - Masquerade as a normal installer while laying down files in sensitive spots

After it’s done? The malware can flip redirection back on like nothing happened using `Wow64RevertWow64FsRedirection`. One call to slip past the bouncer, another to blend back into the crowd. It’s not flashy. It’s not noisy. But it rewrites what you think you’re seeing—and that makes it dangerous.

** Why not just compile malware for 64-bits? **
Most malware authors could go full 64-bit, but why bother? 32-bit code runs everywhere—on 32- and 64-bit Windows alike. It’s the ultimate compatibility hack. Build one 32-bit loader and it just works, no matter the system. No juggling different versions, no worrying about bitness mismatches. It’s simpler, cleaner, and lets them focus on the payload instead of the platform. When they need to play in the 64-bit world, they just call `Wow64DisableWow64FsRedirection` and slip right in. Smart, stealthy, and annoyingly effective.

## 🛡️ Detection Opportunities
Watch for 32-bit processes calling `Wow64DisableWow64FsRedirection`, that’s your first red flag. Legitimate software rarely needs to disable file system redirection except during installs or specific compatibility scenarios. If you see it in a running app that’s not an installer or updater, start asking questions.

Pair that with suspicious activity like writing to or loading executables from `C:\Windows\System32` from a 32-bit process, especially if there’s no matching parent installer or update flow. Look for the telltale flip-flop: `Wow64DisableWow64FsRedirection` called, followed by file writes or process launches targeting 64-bit system paths, then `Wow64RevertWow64FsRedirection` to clean up.

It goes without saying ...  monitor for evasive chains where malware drops 64-bit payloads under the radar or spawns 64-bit tools from 32-bit hosts. Unexpected 64-bit activity originating from 32-bit processes is a smoking gun.

Context is king: a call to disable redirection alone isn’t always evil, but combined with other stealthy behaviors, it’s a clear sign someone’s trying to bend Windows’ rules.

## 🦠 Malware & Threat Actors Documented Abusing Wow64DisableWow64FsRedirection

### Ransomware
 - Darkrace 
 - Dharma
 - Maze
 - Prestige
 - Rook

### Commodity Loaders & RATs
 - HermeticWiper
 - LegionLoader
 - StrRat
 - TrickBot Loader
 - Warzone RAT 

### APT & Threat Actor Toolkits
 - Donot
 - Mustang Panda
 - Sandworm

### Red Team & Open Source Tools
 - Cobalt Strike
 - Metasploit

> **Note:** This list isn't exhaustive. Many modern malware families and offensive security tools could use `Wow64DisableWow64FsRedirection`.

## 🧵 `Wow64DisableWow64FsRedirection` and Friends
`Wow64DisableWow64FsRedirection` doesn’t fly solo. It usually teams up with `Wow64RevertWow64FsRedirection` to toggle redirection off and on like a light switch. There’s also `Wow64DisableWow64FsRedirectionEx`, a sharper, thread-focused sibling that gives attackers more control. And then there’s `Wow64SetThreadDefaultGuestMachine`, which tweaks how threads see the 32- vs 64-bit world. These APIs all mess with Windows’ compatibility layers, quietly rewriting the rules for how processes see the file system and environment. Rarely touched by legit apps, but a sweet spot for stealthy malware and red team tricks.

## 📚 Resources
 - Microsoft: [Wow64DisableWow64FsRedirection](https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-wow64disablewow64fsredirection)
 - MITRE: [Native API](https://attack.mitre.org/techniques/T1106/)
 - [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas) (more like this)

> **Know of more?**  
> Open a PR or issue to help keep this list up to date!