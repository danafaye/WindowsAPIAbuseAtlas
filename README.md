# WindowsAPIAbuseAtlas
WindowsAPIAbuseAtlas is an evolving map of the sneaky and lesser-known ways malware twists Windows APIs to hide, evade, and attack. It’s packed with practical reverse engineering insights, ready-to-use YARA rules, and clear behavioral clues that help defenders spot these tricks in the wild. Whether you’re hunting threats, building detections, or just curious about how bad actors operate behind the scenes, this atlas sheds light on complex Windows behavior — empowering the cyber community to stay one step ahead.

# Index
This is a living roadmap. As I knock out each entry, I’ll link it here. If you don’t see a link yet, it’s just a placeholder for something I’ll probably get to ... or at least something worth keeping on the radar.

## 🧠 Thread & Execution Hijacking

- `NtQueueApcThread`
- [NTDLL/NtSetInformationThread](./NTDLL/NtSetInformationThread/README.md)
- `NtResumeThread`
- `NtAlertResumeThread`
- `QueueUserAPC` *(less stealthy, but still relevant)*
- `RtlCreateUserThread`
- `NtCreateThreadEx`
- `CreateRemoteThreadEx`
- `SetThreadContext` / `GetThreadContext`

## 🧬 Memory & Mapping Abuse

- `NtCreateSection`
- `NtMapViewOfSection`
- `NtUnmapViewOfSection`
- `VirtualAllocEx`
- `WriteProcessMemory`
- `NtProtectVirtualMemory`
- `NtWriteVirtualMemory`
- `NtReadVirtualMemory`

## 🕵️ Process Masquerading / Evasion

- `NtSetInformationProcess`
- `NtQueryInformationProcess`
- `UpdateProcThreadAttribute`
- `CreateProcessInternalW`
- `SetProcessMitigationPolicy`

## 🩺 Telemetry & Anti-Detection

- [NTDLL/EtwEventWrite](./NTDLL/EtwEventWrite/README.md)
- `EtwNotificationRegister`
- `EtwProviderEnabled`
- `NtTraceEvent`
- `NtSetDebugFilterState`
- `DbgUiRemoteBreakin`

## 🔐 Token & Privilege Abuse

- `AdjustTokenPrivileges`
- `OpenProcessToken`
- `DuplicateTokenEx`
- `NtImpersonateThread`
- `ImpersonateLoggedOnUser`
- `NtSetInformationToken`

## 🎭 DLL/PE Loading Tricks

- `LdrLoadDll`
- `LdrGetProcedureAddress`
- `NtOpenFile` + `NtCreateSection` *(manual mapping)*
- `MapViewOfFile` + `LoadLibraryA/W`
- `SetDllDirectoryA/W` + `LoadLibrary`

## 🧩 Service, Registry & Misc Control

- `RegSetValueEx`
- `RegCreateKeyEx`
- `OpenSCManager`
- `CreateService`
- `ControlService`
- `NtDeviceIoControlFile`
