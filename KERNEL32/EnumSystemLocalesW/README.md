# 🧪 EnumSystemLocalesW

## 🚀 Executive Summary
`EnumSystemLocalesW` doesn’t look dangerous—but that’s what makes it interesting. It’s obscure, boring, and forgotten by most detection engines. But hand it the right pointer, and this quiet little API becomes a signed execution launcher. No threads, no syscalls, no noise, just Windows doing what it was told. Attackers who know about it can fly straight through most defenses, and defenders who ignore it miss a chance to spot truly low-volume, high-intent behavior. It’s not flashy, but it’s a trapdoor. Keep an eye on it.

## 🔍 What is EnumSystemLocalesW?
`EnumSystemLocalesW` walks through the list of locales installed on the system and calls a function you give it once for each one. That’s it. You hand it a callback, and Windows starts feeding it locale identifiers like `en-US` or `fr-FR`. Legit uses are usually around language selection or region-aware formatting. Think installers, UI frameworks, or setup wizards trying to be polite. It’s not flashy, but it’s handy if you need to know what cultures the system speaks. It’s also old and kind of niche, modern apps often just grab the current locale and move on. So when this API shows up in something that isn’t localization-related, it’s probably not about regional preferences.

## 🚩 Why It Matters
This API takes a function pointer and calls it: OVER-and-OVER. That alone should set off alarms. Most software has no reason to iterate through locales, and even less reason to do it by **executing arbitrary callbacks**. For red teamers, it’s a low-noise way to kick off code under the radar. For blue teamers, it’s a weird, rare signal that’s easy to miss but high in intent when it shows up. It’s quiet, signed, and rarely questioned. Which is exactly why you should question it.

## 🧬 How Attackers Abuse It
Attackers abuse `EnumSystemLocalesW` by handing it a fake callback, usually a pointer to shellcode sitting in memory. Windows, being helpful, calls that pointer repeatedly, *no questions asked*. It’s perfect for trampolining: instead of jumping straight to malicious code (which might get flagged), they let a signed Windows API do the honors. No thread creation, no direct calls, no new modules loaded, just execution handed off politely by the OS. It blends in, especially when sandwiched between legitimate-looking behavior. You won’t see `CreateThread`, but things are running. You won’t see a loader, but shellcode’s firing. This is what quiet execution looks like.

## 🛡️ Detection Opportunities
Legit software almost never calls `EnumSystemLocalesW`, and when it does, it’s usually once, during install, setup, or localization. So when it shows up mid-flow in a process that isn’t language-aware, that’s weird, and weird is a thing to chase down. Watch for it paired with executable memory, especially if the callback address isn’t tied to a loaded module. No .dll, no symbol, just some sketchy heap or RWX region? That’s your tell. Bonus points if it follows `VirtualAlloc` or `WriteProcessMemory`, or happens in a process that has no business caring about system locales, like a tax tool or audio driver.

## 🦠 Malware & Threat Actors Documented Abusing EnumSystemLocalesW Patching
Below is a curated list of malware families, threat actors, and offensive tools known to abuse or patch `EnumSystemLocalesW` for defense evasion.  

For the latest technical write-ups, search for the malware or tool name together with "EnumSystemLocalesW" on reputable security blogs, threat intelligence portals, or simply google. (Direct links are not included to reduce maintenance.)

It’s subtle, but not convenient. `EnumSystemLocalesW` *can* trampoline into shellcode, but it needs a proper function signature, gets called multiple times, and doesn’t give much control over timing or arguments. That makes it clunky for most real-world malware, which prefers APIs that are easier to bend, like `CreateThread`, `NtContinue`, or `RtlCreateUserThread`. It’s also a little dated; modern loaders and frameworks go for techniques with better payload handling and fewer surprises. So while it’s technically abusable and interesting from a research perspective, it hasn’t made the jump to widespread adoption. Yet.

### **Ransomware**
 - Couldn't find one, let me know if you do.

### **Commodity Loaders & RATs**
 - Hooka
 - ValleyRAT

 ### **APT & Threat Actor Toolkits**
 - Curiously, none? This can't be true.

### **Red Team & Open Source Tools**
 - https://github.com/aahmad097/AlternativeShellcodeExec 

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `EnumSystemLocalesW` for stealth and evasion.

## 🧪 Other Enum* APIs That Can Be Abused
Windows is full of friendly `Enum*` functions that take callbacks and just… call them, no questions asked. If you can point them at shellcode, they’ll happily trampoline execution for you. Besides `EnumSystemLocalesW`, you’ve got `EnumWindows`, `EnumChildWindows`, `EnumThreadWindows`, `EnumDesktops`, `EnumFontFamiliesEx`, and even `EnumDateFormatsEx`. All of them work the same way: give it a pointer, and it runs your code in a loop. Most were built for GUI or localization tasks, but malware doesn’t care. If it calls back, it can be hijacked. Think of them as polite little execution launchers just waiting for someone to aim them wrong.

## 📚 Resources 
* Microsoft Docs: [EnumSystemLocalesW](https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumsystemlocalesa)
* MITRE: [Process Injection](https://attack.mitre.org/techniques/T1055/)
* [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas) (More like this)

> **Know of more?**  
> Open a PR or issue to help keep this list up to date!
