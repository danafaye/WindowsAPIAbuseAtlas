# 🛠️ SHGetKnownFolderPath: 

## 🚀 Executive Summary
`SHGetKnownFolderPath` is a Windows Shell API function that returns the full path of a known folder like the Desktop, Documents, AppData, or Startup directories. While legitimate software uses it to quickly locate standard OS folders, attackers abuse it to locate persistence friendly directories, hide malicious files in obscure locations, or target sensitive data stores. This API appears in commodity malware, advanced persistent threats (APTs), and red team tooling alike making it a useful hunting pivot when seen in combination with suspicious file or process creation.

## 🔍 What is SHGetKnownFolderPath?
This Shell API (exported from shell32.dll) accepts a folder GUID and returns its corresponding file system path. For example, `FOLDERID_Startup` maps to the user’s Startup directory, while `FOLDERID_LocalAppData` points to %LOCALAPPDATA%.

[Microsoft Documentation for Folder GUIDs](https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid)

## 🚩 Why It Matters
By resolving paths dynamically, malware can adapt to any user profile or Windows version, making it more portable and stealthy. Targeted folders often contain startup scripts, cached credentials, or sensitive documents, making them ideal for persistence, staging, or theft.

## 🧬 How Attackers Abuse It
Malware has used this API to find the Startup folder for auto run payloads, identify AppData for staging malicious files, and locate user specific data stores for exfiltration. This avoids brittle hardcoded paths and blends malicious behavior into normal system calls.

## 🛡️ Detection Opportunities
Correlate `SHGetKnownFolderPath` calls with suspicious follow on actions like file creation in Startup, AppData, or Temp. Monitor for this API preceding script drops, executable writes, or process launches from those directories.

Here are some sample YARA rules to detect suspicious use of `SHGetKnownFolderPath`:

See [SHGetKnownFolderPath.yar](./SHGetKnownFolderPath.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - Startup folder resolved → new .vbs, .bat, .lnk, or executable file created.
 - LocalAppData resolved → file write followed by network activity.

## 🦠 Malware & Threat Actors Documented Abusing SHGetKnownFolderPath

### **Ransomware**
 - DarkHotel
 - SugarLocker

### **Commodity Loaders & RATs**
 - JellyDust
 - RoKRAT

### **APT & Threat Actor Toolkits**
 - APT37
 - APT41  

### **Red Team & Open Source Tools**
 - Cobalt Strike
 - Empire
 - Power Sploit

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `SHGetKnownFolderPath`.

## 🧵 `SHGetKnownFolderPath` and Friends
Related APIs include SHGetFolderPath (legacy), SHGetKnownFolderIDList (returns ITEMIDLIST), and ExpandEnvironmentStrings (environment variable–based path resolution).

## 📚 Resources
  [Microsoft Docs: SHGetKnownFolderPath](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath)
  [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!