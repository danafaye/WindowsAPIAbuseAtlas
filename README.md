# Windows API Abuse Atlas
WindowsAPIAbuseAtlas is an evolving map of the sneaky and lesser-known ways malware twists Windows APIs to hide, evade, and attack. It’s packed with practical reverse engineering insights, ready-to-use YARA rules, and clear behavioral clues that help defenders spot these tricks in the wild. Whether you’re hunting threats, building detections, or just curious about how bad actors operate behind the scenes, this atlas sheds light on complex Windows behavior ... empowering the cyber community to stay one step ahead.

# Index
This is a living roadmap. As I knock out each entry, I’ll link it here. If you don’t see a link yet, it’s just a placeholder for something I’ll probably get to ... or at least something worth keeping on the radar.

## 🧠 Thread & Execution Hijacking

- `CreateFiber` / `ConvertThreadToFiber`
- `CreateRemoteThreadEx`
- [NTDLL/NtQueueApcThread](./NTDLL/NtQueueApcThread/)
- [NTDLL/NtSetInformationThread](./NTDLL/NtSetInformationThread/)
- `NtAlertResumeThread`
- `NtCreateThreadEx`
- `NtResumeThread`
- `NtOpenThread`
- `QueueUserAPC` *(less stealthy, but still relevant)*
- `RtlCreateUserThread`
- `SetThreadContext` / `GetThreadContext`

## 🧬 Memory & Mapping Abuse

- [NTDLL/NtCreateSection](./NTDLL/NtCreateSection/)
- `NtAllocateVirtualMemory`
- [NTDLL/NtMapViewOfSection](./NTDLL/NtMapViewOfSection/)
- `NtProtectVirtualMemory`
- `NtReadVirtualMemory`
- `NtUnmapViewOfSection`
- [NTDLL/NtWriteVirtualMemory](./NTDLL/NtWriteVirtualMemory/)
- `VirtualAllocEx`
- `WriteProcessMemory`

## 🕵️ Process Masquerading / Evasion

- `CreateProcessAsUserW`
- `CreateProcessInternalW`
- `CreateProcessWithTokenW`
- [PSAPI/EnumProcessModules](./PSAPI/EnumProcessModules/)
- `NtQueryInformationProcess`
- `NtSetInformationProcess`
- `NtSetInformationFile`
- `SetProcessMitigationPolicy`
- [KERNEL32/UpdateProcThreadAttribute](./KERNEL32/UpdateProcThreadAttribute/)

## 🩺 Telemetry & Anti-Detection

- [NTDLL/DbgUiRemoteBreakin](./NTDLL/DbgUiRemoteBreakin/)
- [NTDLL/EtwEventWrite](./NTDLL/EtwEventWrite/)
- `EtwNotificationRegister`
- `EtwProviderEnabled`
- `NtRaiseHardError`
- `NtSetDebugFilterState`
- `NtTraceEvent`
- `Wow64DisableWow64FsRedirection`

## 🔐 Token & Privilege Abuse

- `AdjustTokenPrivileges`
- `DuplicateTokenEx`
- `ImpersonateLoggedOnUser`
- [NTDLL/NtImpersonateThread](./NTDLL/NtImpersonateThread/)
- `NtSetInformationToken`
- `OpenProcessToken`

## 🎭 DLL/PE Loading Tricks

- `LdrGetProcedureAddress`
- `LdrLoadDll`
- `MapViewOfFile` + `LoadLibraryA/W`
- `NtOpenFile` + `NtCreateSection` *(manual mapping)*
- `SetDllDirectoryA/W` + `LoadLibrary`

## 🧩 Service, Registry & Misc Control

- [NTDLL/NtDeviceIoControlFile](./NTDLL/NtDeviceIoControlFile/)
- `ControlService`
- `CreateService`
- `OpenSCManager`
- `RegSetValueEx`

## 🧭 Recon & Enumeration

- [NETAPI32/NetLocalGroupGetMembers](./NETAPI32/NetLocalGroupGetMembers/)
- `NetSessionEnum`
- `NetWkstaUserEnum`
- `WNetEnumResource`

## 🪪 Credential Access & Secret Extraction

- [LsaRetrievePrivateData](./ADVAPI32/LsaRetrievePrivateData/)
- `CryptUnprotectData`
- `CredReadW`
- `CredEnumerateW`
- `LsaOpenPolicy`


