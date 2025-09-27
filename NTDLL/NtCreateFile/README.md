# 📂 NtCreateFile 

## 🚀 Executive Summary
`NtCreateFile` is the native syscall that actually makes Windows hand you a handle to “file like” objects.  It's a little confusing because it works for **files, pipes, devices, volume handles**. And attackers lean on it to drop, lock, or access artefacts people assume are “just normal files.” If you watch for odd namespaces, exclusive open patterns, and unexpected native-syscall usage, you’ll catch staging, ransomware locking, and low-level device tampering before the malware announces itself.

## 🔍 What is NtCreateFile?
`NtCreateFile` is the ntdll→kernel gate for creating or opening objects backed by the filesystem or device namespace. It takes `OBJECT_ATTRIBUTES` (so the full kernel visible name), an access mask, create disposition, share flags, and a set of options that change semantics (directory vs file, synchronous vs asynchronous, open by file id). Everything a `CreateFileW` call does winds up here. Plus things user APIs won’t touch, like raw volume/device opens and GLOBALROOT shenanigans.

## 🚩 Why It Matters
Because `NtCreateFile` exposes intent that higher level APIs can hide. The kernel visible path (`\Device`, `\??\GLOBALROOT`, `\.\PhysicalDrive`, shadow copy names), the disposition (create vs overwrite), and the access/share bits tell you whether a process is staging, trying to gain exclusive access to destroy backups, or probing low-level devices. Attackers abuse those affordances to avoid hooks, hold files while encrypting them, and access recovery artifacts; defenders who instrument NtCreateFile see the intent earlier and with better context.

## 🧬 How Attackers Abuse It
Malware uses `NtCreateFile` to plant payloads in odd corners (deep profile paths, ADS, installer like names), to open named pipes and device objects for C2 or credential capture, and to grab exclusive handles during encryption. Ransomware opens tens to hundreds of files with write/create dispositions and exclusive share modes, writing encrypted content back to the same handle. Loaders resolve `NtCreateFile` dynamically or emit direct syscalls to evade usermode hooks. Advanced actors open `\Device\HarddiskVolumeShadowCopy` or physical drive handles to tamper with backups or read raw data. If you see a process that normally talks HTTP suddenly resolving ntdll exports and creating device objects, that’s not a mistaken import. It’s intent.

## 🛡️ Detection Opportunities
Telemetry you can actually act on: kernel visible object names (`\Device\`, `\??\GLOBALROOT\`, `\?\Volume{...}`, `\.\PhysicalDrive`), create disposition combined with exclusive share flags, high rate create/open cycles from non I/O processes, and dynamic resolution + direct syscall behavior. Hunt for processes that create files in profile temp paths but with executable extensions and ADS, for exclusive opens followed immediately by large synchronous writes, and for any NtCreateFile that targets volume/shadow-copy or physical device namespaces. Correlate with parent/child lineage, thread injection, and DeviceIoControl sequences — the composite story separates installer noise from malicious staging.

Here are some sample YARA rules to detect suspicious use of `NtCreateFile`:

See [NtCreateFile.yar](./NtCreateFile.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - Look for short lived processes that resolve `NtCreateFile` and then spawn write heavy file churn; exclusive opens (deny read/deny write) across many user documents followed by content overwrite.

 - Creation of objects under `\Device` or `GLOBALROOT`

 - Named pipe creation immediately followed by remote network endpoints

 - Sudden volume/physical drive opens by processes that never needed block level access. 

## 🦠 Malware & Threat Actors Documented Abusing NtCreateFile

### **Ransomware**
- BlackByte 
- Play
- Storm-2460

### **Commodity Loaders & RATs**
- Dridex 
- Formbook
- TrickBot

### **APT & Threat Actor Toolkits**
- Gothic Panda 
- Hidden Cobra
- Fancy Bear

### **Red Team & Open Source Tools**
- AutoRDPwn
- Empire
- Metasploit

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `NtCreateFile`.

## 🧵 `NtCreateFile` and Friends
Think of these as the “family” of file and device entry points: `CreateFileA`/`CreateFileW`, `ZwCreateFile`/`NtOpenFile`, `NtReadFile`/`NtWriteFile`, `NtQueryAttributesFile`, `DeviceIoControl`, and the various file-mapping APIs. Plus the named pipe and device namespace helpers; all expose overlapping functionality or work on the same kernel objects that `NtCreateFile` does, so they’re the natural places to look when you want other ways to open, query, map, or control the same targets.

## 📚 Resources
- [Microsoft Docs: NtCreateFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!