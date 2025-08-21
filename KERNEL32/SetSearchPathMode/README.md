# 🛠️ SetSearchPathMode: 

## 🚀 Executive Summary
`SetSearchPathMode` controls how Windows resolves relative paths when loading executables, libraries, and other files. While seemingly benign, it has big implications for how a processes locates dependencies. Attackers can leverage this API to force Windows to look in attacker controlled locations first, enabling DLL hijacking, side loading, or execution of rogue binaries. Understanding its abuse potential helps defenders detect subtle persistence and evasion techniques.

## 🔍 What is SetSearchPathMode?
This API configures the search order Windows uses when resolving relative paths. By default, Windows has a layered search strategy checking the application’s directory, system directories, current working directory, and PATH locations. With `SetSearchPathMode`, a process can override that behavior, telling Windows to prioritize certain directories over others.

It takes one "flag" parameter that defines the search mode. For example:
- `BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE` enforces safer rules (system directories first).
- `BASE_SEARCH_PATH_PER_USER_ENABLE` allows user specific search paths to be included.

Legitimate software often calls this API to tighten security or ensure consistent file loading. Attackers, however, may flip it in the opposite direction to loosen rules and funnel execution toward malicious files.

## 🚩 Why It Matters
Path resolution is a choke point where trust boundaries blur. If an attacker can influence search order, they can slip malicious DLLs or executables into the loading chain. This enables:

- **Privilege escalation** by dropping a DLL where a privileged process will find it.
- **Evasion** by avoiding stricter Windows defaults like Safe DLL Search Mode.
- **Persistence** if the altered search mode keeps pointing to attacker controlled paths across sessions.

The risk isn’t just theoretical; path redirection has been a building block in countless campaigns.

## 🧬 How Attackers Abuse It
Attackers abuse `SetSearchPathMode` by reshaping the rules Windows uses to decide where to look first when a process requests a DLL or executable. Instead of respecting the safer defaults, which generally prioritize trusted system directories like System32. Adversaries can flip the mode so that Windows favors the current working directory or per user paths. Once that’s done, they only need to drop a malicious DLL with the same name as a legitimate one into that directory. When the process later calls `LoadLibrary`, `LoadLibraryEx`, or even indirectly loads dependencies through `CreateProcess`, Windows happily resolves the attacker’s payload first.

This is especially dangerous in scenarios where applications use relative paths instead of absolute ones. A benign `LoadLibrary("myhelper.dll")` call suddenly turns into an execution sinkhole: if `SetSearchPathMode` has been adjusted, Windows may skip over `System32\myhelper.dll` and grab a trojanized `.\myhelper.dll` from the attacker’s folder.

The API is rarely abused in isolation. Attackers often pair it with:

 - `SetDllDirectory`to explicitly insert an attacker-controlled directory into the search path after relaxing the search rules.
 - `CreateProcess` or `CreateProcessAsUser` or `CreateProcessWithTokenW` to launch new processes that inherit the manipulated search behavior, ensuring persistence or execution of malicious libraries across process lifetimes.
 - `WriteProcessMemory` and `CreateRemoteThread` to inject code into a target process that calls `SetSearchPathMode` internally, effectively hijacking its DLL search order without touching the binary on disk.

From a tradecraft perspective, this technique is valuable because it *doesn’t require elevated privileges or kernel exploits*. It’s a quiet manipulation of a builtin rule set, which means defenders might miss it unless they are explicitly correlating `SetSearchPathMode` activity with subsequent DLL loads.

**TLDR**: The abuse pattern looks like this; change the search rules using `SetSearchPathMode`, prepare a malicious DLL in a directory Windows will now prioritize, then trigger a load via `LoadLibrary` or a process creation API. It’s not flashy, but it’s effective and blends well with normal Windows behavior.

## 🛡️ Detection Opportunities
Catching abuse of `SetSearchPathMode` requires looking at the bigger picture. Plenty of legitimate software will invoke it, so the real signal emerges when the call is followed by suspicious behavior. For instance, a process that disables Safe DLL Search Mode and then immediately loads a DLL from a user writable directory should raise eyebrows. Similarly, processes that normally have no business manipulating search paths, but suddenly start doing so before spawning child processes, deserve closer inspection.

Telemetry from ETW, Sysmon, or EDR can help connect the dots, especially when `SetSearchPathMode` activity aligns with `LoadLibrary`, `CreateProcess`, or unexpected DLL loads.

Here are some sample YARA rules to detect suspicious use of `SetSearchPathMode`:

See [SetSearchPathMode.yar](./SetSearchPathMode.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - DLL loads from user-writable paths after `SetSearchPathMode`. 
 - Execution of binaries via relative paths.
 - Processes disabling safe search mode without a clear reason.

## 🦠 Malware & Threat Actors Documented Abusing SetSearchPathMode
There’s limited public reporting that names `SetSearchPathMode` directly, but it lines up neatly with long standing attacker behavior around DLL search order hijacking. Ransomware families, commodity loaders, and advanced threat actors alike have relied on path manipulation for years, and this API provides a direct way to implement it. Even if not explicitly called out in malware writeups, it’s worth assuming that both red teams and real adversaries know how to take advantage of it.

## 🧵 `SetSearchPathMode` and Friends
This API rarely works in isolation. It’s most dangerous when paired with loaders like `LoadLibrary` or process creation functions that rely on relative paths. It also overlaps conceptually with registry keys that configure Safe DLL Search Mode. Together, these techniques form a cluster of tricks attackers use to make Windows fetch code from locations it normally wouldn’t.

It’s also worth noting the relationship with `SetDllDirectory`. While `SetSearchPathMode` defines *how* Windows prioritizes its search paths, `SetDllDirectory` explicitly adds or removes directories from that search list. In practice, attackers might use them together. First altering the search order with `SetSearchPathMode`, then pointing Windows toward a malicious directory with `SetDllDirectory`. The combination gives precise control over both the rules and the locations Windows will consult, making it a versatile way to hijack DLL loading.

## 📚 Resources
- [Microsoft Docs: SetSearchPathMode](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setsearchpathmode)
- [Check Point: 10 Years of DLL Hijacking, and What We Can Do to Prevent 10 More](https://research.checkpoint.com/2024/10-years-of-dll-hijacking-and-what-we-can-do-to-prevent-10-more/)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!