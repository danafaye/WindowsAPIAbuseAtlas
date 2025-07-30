# 📷 PssCaptureSnapshot: Process Peephole

## 🚀 Executive Summary
`PssCaptureSnapshot` is a Windows API designed to capture detailed, live snapshots of running processes like memory, handles, and threads. Built for diagnostics and debugging, it enables efficient and flexible data collection with minimal impact on the target. While its capabilities make it an attractive option for process memory analysis, publicly observed malicious use remains limited (from what I can see and have access to). However, its potential for stealthy data extraction and in-memory analysis warrants close attention from defenders aiming to stay ahead of emerging threats.

## 🔍 What is PssCaptureSnapshot?
`PssCaptureSnapshot` is part of the Process Snapshotting API, introduced in Windows 8.1 to support lightweight, live snapshots of running processes. It allows tools to capture memory, handles, threads, and other process context without suspending or terminating the target. Microsoft uses this internally for diagnostics like Task Manager or Windows Error Reporting gathering data from a hung process. Unlike traditional dump APIs, this one gives control over what gets collected, making it faster and more targeted.

## 🚩 Why It Matters
`PssCaptureSnapshot` offers a way to take a detailed snapshot of a running process. For things like memory, handles, threads, and more; all without stopping or crashing it. It’s quieter and more flexible than traditional dumping methods, and doesn’t always require full debugging privileges. This makes it useful not just for diagnostics, but for any scenario where collecting process data with minimal footprint is the goal. Its snapshots can be passed around or analyzed later, making it a valuable tool in both legitimate and suspicious hands.

## 🧬 How Attackers Abuse It
Malware uses `PssCaptureSnapshot` as a stealthier alternative to classic process dumping techniques. Instead of using `MiniDumpWriteDump` or suspending processes outright, threat actors can capture a live snapshot of a target (LSASS) without triggering common EDR hooks or dump heuristics. The resulting snapshot handle can then be passed to `PssQuerySnapshot` and `PssWalkMarker` to iterate through memory regions or extract credential material. 

Unlike [CreateToolhelp32Snapshot](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/KERNEL32/CreateToolhelp32Snapshot), which gives a basic static view of process, thread, or module lists, `PssCaptureSnapshot` offers a far deeper and more flexible snapshot. Toolhelp32 is noisy, limited, and mostly useful for enumeration. PSS lets you grab memory, handles, threads, context ... all in one go, and without stopping the process. Toolhelp is a survey tool; PSS is full access without the mess. One is often flagged. The other is still flying under the radar.

## 🛡️ Detection Opportunities
Here are some sample YARA rules to detect suspicious use of `PssCaptureSnapshot`:

See [PssCaptureSnapshot.yar](./PssCaptureSnapshot.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - Unexpected process snapshots of LSASS or other sensitive processes: Look for `PssCaptureSnapshot` targeting LSASS, winlogon, or other security critical processes, especially from untrusted processes.
 - Snapshot creation followed by memory access without a dump file: 
A telltale sign: no `MiniDumpWriteDump`, no `.dmp` on disk, but memory gets parsed. Follow-on API usage like `PssQuerySnapshot`, `PssWalkMarker`, or direct reads from snapshot memory regions are strong indicators.
 - Use of `PssCaptureSnapshot` from non-Microsoft signed binaries
Most legitimate usage comes from Task Manager or WerFault. Anything unsigned or custom-built using this API warrants scrutiny.
 - Use of snapshot APIs in short-lived or ephemeral processes: 
Malicious snapshot operations are often grab memory, parse it, and exit. Look for processes that launch, snapshot LSASS, and terminate within seconds.
 - Snapshot APIs combined with obfuscation or indirect resolution: Calls to `PssCaptureSnapshot` resolved at runtime via `GetProcAddress`, `LoadLibrary`, or manually parsed export tables indicate attempts to hide usage.
 - Abuse via LOLBins: Some attackers hijack or side-load legitimate signed binaries (WerFault.exe) to invoke snapshot routines. Check parent/child relationships and command-line args for signs of abuse.

### Reverse Engineering Tips
 - Look for usage of `PssCaptureSnapshot`: Start with IAT or dynamic imports. If statically linked, it will show under kernel32; otherwise, track runtime resolution via `GetProcAddress`.
 - Watch for snapshot type flags in the call: The second parameter (`PSS_CAPTURE_FLAGS`) is where intent shows. Look for flags like `PSS_CAPTURE_VA_CLONE`, `PSS_CAPTURE_HANDLES`, `PSS_CAPTURE_HANDLE_NAME_INFORMATION`, or `PSS_CAPTURE_THREADS`.
 - Correlate with `PssQuerySnapshot` and `PssWalkMarker`: Dumping isn’t one-and-done. `PssCaptureSnapshot` creates the object, but walking through memory comes next. Look for loops walking memory markers or dumping handle information.
 - Monitor for API chains that snapshot → extract → destroy: A typical malicious flow is `PssCaptureSnapshot` → `PssQuerySnapshot`/`PssWalkMarker` → parsing routines → `PssFreeSnapshot`.
 - Look for credential extraction patterns after snapshot: Watch for string parsing, LSASS specific memory markers, `lsasrv.dll` references, or kerberos, msv1_0, wdigest module strings shortly after snapshotting.
 - Check for direct syscall usage (rare but possible): Advanced tooling may bypass the API layer entirely, invoking syscalls directly via syscall stubs or shellcode wrappers for PSS-related functions. (`NtReadVirtualMemory`, `NtQueryVirtualMemory`, `NtPssCaptureSnapshot`, probably more)

## 🦠 Malware & Threat Actors Documented Abusing PssCaptureSnapshot
Notably, variants of Cobalt Strike, Mimikatz forks, and newer post exploitation frameworks have integrated this method to bypass dump detection rules and reduce forensic noise. Because it doesn’t write a dump to disk by default, and the snapshot can be held entirely in memory, it often slips under the radar of traditional detection pipelines. This API is also increasingly seen in LOLBin scenarios, where signed binaries (like Task Manager or WerFault) are abused to invoke snapshotting indirectly.

Oddly, there are lots of write-ups describing this technque that mention ransomware or malware in general, but I couldn't find any named tool or specific reverse engineer focused write-ups that call out this technique in use specifically?  Let me know if you know of one.

### **Red Team & Open Source Tools**
 - ATPMiniDump
 - CredBandit
 - Cobalt Strike
 - Mimikatz (some versions)

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `PssCaptureSnapshot`.

## 🧵 `PssCaptureSnapshot` and Friends
`PssCaptureSnapshot` rarely works alone. It’s usually followed by `PssQuerySnapshot` to extract metadata or memory sections, and `PssWalkMarker` to iterate over snapshot contents. After data is harvested, `PssFreeSnapshot` cleans up. In malicious use, it’s often paired with APIs like `NtReadVirtualMemory` for direct access, or `OpenProcess` and `GetProcAddress` when snapshots are wrapped in obfuscation. Some tooling adds `CreateToolhelp32Snapshot` or `MiniDumpWriteDump` as fallbacks, switching techniques based on permission or detection. When used to target LSASS, expect to see supporting calls like `LookupPrivilegeValue`, `AdjustTokenPrivileges`, and `OpenProcessToken` to quietly secure `SeDebugPrivilege` first.

## 📚 Resources
- [Microsoft Docs: PssCaptureSnapshot](https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/nf-processsnapshot-psscapturesnapshot)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)
- [matteomalvica\.com](https://www.matteomalvica.com/blog/2019/12/02/win-defender-atp-cred-bypass/)

> Open a PR or issue to help keep this list up to date!