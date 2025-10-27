# 🛠️ `MiniDumpWriteDump` 

## 🚀 Executive Summary
`MiniDumpWriteDump` is a legitimate Windows API designed to generate process memory dumps, a core function in debugging and crash analysis. But in the wrong hands, it’s a red-team and adversary favorite for credential theft, process introspection, and memory scraping. Attackers routinely weaponize this API to dump the memory of processes like lsass.exe, harvesting plaintext passwords and hashes directly from memory.

## 🔍 What is `MiniDumpWriteDump`?
`MiniDumpWriteDump` resides in dbghelp.dll and allows developers (or attackers) to capture the memory of a target process and write it to a dump file. The function can capture different levels of detail from basic thread and module lists to full memory snapshots depending on the specified dump type.

Prototype:
```
BOOL MiniDumpWriteDump(
  HANDLE hProcess,
  DWORD ProcessId,
  HANDLE hFile,
  MINIDUMP_TYPE DumpType,
  PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
  PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
  PMINIDUMP_CALLBACK_INFORMATION CallbackParam
);
```

When abused, it’s typically called with parameters that capture all accessible memory regions of the target process, commonly MiniDumpWithFullMemory.

## 🚩 Why It Matters
Memory dumps are a goldmine. When `MiniDumpWriteDump` is used against processes like LSASS, LSAISO, or SAMSRV, it can expose credentials, Kerberos tickets, and secrets stored in process memory. This is one of the most common and reliable techniques for credential dumping, and it’s been seen in everything from nation-state intrusions to commodity stealers.

## 🧬 How Attackers Abuse It
Threat actors typically:

 1. Obtain a handle to a sensitive process (like lsass.exe) using OpenProcess with PROCESS_VM_READ | PROCESS_QUERY_INFORMATION access.
 2. Create or open a dump file using CreateFileW.
 3. Call `MiniDumpWriteDump` with MiniDumpWithFullMemory or similar flags.
 4. Optionally encrypt or exfiltrate the resulting dump file.

Malware often loads dbghelp.dll dynamically to evade static detection, sometimes using indirect calls or reflective loading to further obscure behavior.

## 🛡️ Detection Opportunities
Telemetry to monitor:

 - `MiniDumpWriteDump` calls from non-debugging processes (like PowerShell, cmd.exe, svchost.exe).
 - Suspicious handles to LSASS (PID of lsass.exe) obtained by non-system processes.
 - Creation of .dmp files in unusual directories (%TEMP%, %APPDATA%, or public folders).
 - Dynamic loading of dbghelp.dll via LoadLibrary or GetProcAddress.

Here are some sample YARA rules to detect suspicious use of ``MiniDumpWriteDump``:

See [`MiniDumpWriteDump`.yar](./`MiniDumpWriteDump`.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - dbghelp.dll loaded by non-debugging software.
 - File creation followed by WriteFile patterns indicative of a dump file.
 - Memory access events on lsass.exe from unexpected users or processes.
 - Processes invoking `MiniDumpWriteDump` shortly after acquiring LSASS handles.
 - Dump files compressed, encrypted, or immediately deleted after creation.

## 🦠 Malware & Threat Actors Documented Abusing `MiniDumpWriteDump`

### **Ransomware**
 - Conti 
 - LockBit
 - Ryuk

### **Commodity Loaders & RATs**
 - Agent Tesla
 - FormBook
 - Remocos RAT

### **APT & Threat Actor Toolkits**
 - APT29 (Cozy Bear)
 - Equation Group

### **Red Team & Open Source Tools**
 - Mimikatz
 - Cobalt Strike

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use ``MiniDumpWriteDump``.

## 🧵 ``MiniDumpWriteDump`` and Friends
 - **DbgHelp.dll**: the library containing `MiniDumpWriteDump`.
 - **OpenProcess**: used to gain a handle to target processes.
 - **CreateFileW / WriteFile**: for writing dump contents.
 - **NtReadVirtualMemory**: alternative method for memory scraping.
 - **DuplicateHandle**: occasionally abused to bypass handle access restrictions.

## 📚 Resources
- [Microsoft Docs: `MiniDumpWriteDump`](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-`MiniDumpWriteDump`)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!