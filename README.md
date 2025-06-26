# Windows API Abuse Atlas
WindowsAPIAbuseAtlas is an evolving map of the sneaky and lesser-known ways malware twists Windows APIs to hide, evade, and attack. It’s packed with practical reverse engineering insights, ready-to-use YARA rules, and clear behavioral clues that help defenders spot these tricks in the wild. Whether you’re hunting threats, building detections, or just curious about how bad actors operate behind the scenes, this atlas sheds light on complex Windows behavior ... empowering the cyber community to stay one step ahead.

# Index
This is a living roadmap. As I knock out each entry, I’ll link it here. If you don’t see a link yet, it’s just a placeholder for something I’ll probably get to ... or at least something worth keeping on the radar.

## ADVAPI32.DLL
- [AdjustTokenPrivileges](./ADVAPI32/AdjustTokenPrivileges/)
- `ControlService`
- `CreateService`
- `CredEnumerateW`
- `CredReadW`
- `DuplicateTokenEx`
- `ImpersonateLoggedOnUser`
- `LsaOpenPolicy`
- [LsaRetrievePrivateData](./ADVAPI32/LsaRetrievePrivateData/)
- `OpenProcessToken`
- `OpenSCManager`
- `QueryServiceStatusEx`
- [RegCreateKeyEx](./ADVAPI32/RegSetValueEx/)
- [RegSetValueEx](./ADVAPI32/RegSetValueEx/)


## KERNEL32.DLL
- `ConvertThreadToFiber`
- `CreateFiber`
- `CreateProcessAsUserW`
- `CreateProcessInternalW`
- `CreateProcessWithTokenW`
- [CreateRemoteThread](./KERNEL32/CreateRemoteThread/)
- `LoadLibraryA/W`
- `MapViewOfFile` + `LoadLibraryA/W`
- `QueueUserAPC`
- `SetDllDirectoryA/W` + `LoadLibrary`
- `SetProcessMitigationPolicy`
- [SetThreadContext](./KERNEL32/SetThreadContext/)
- [UpdateProcThreadAttribute](./KERNEL32/UpdateProcThreadAttribute/)
- `VirtualAllocEx`
- `WriteProcessMemory`
- [WriteProfileString](./KERNEL32/WriteProfileString/)

## NETAPI32.DLL
- [NetLocalGroupGetMembers](./NETAPI32/NetLocalGroupGetMembers/)
- `NetSessionEnum`
- `NetWkstaUserEnum`

## NTDLL.DLL
- [DbgUiRemoteBreakin](./NTDLL/DbgUiRemoteBreakin/)
- [EtwEventWrite](./NTDLL/EtwEventWrite/)
- `EtwNotificationRegister`
- `EtwProviderEnabled`
- `LdrGetProcedureAddress`
- `LdrLoadDll`
- `NtAllocateVirtualMemory`
- `NtAlertResumeThread`
- [NtCreateSection](./NTDLL/NtCreateSection/)
- `NtCreateThreadEx`
- [NtDeviceIoControlFile](./NTDLL/NtDeviceIoControlFile/)
- [NtImpersonateThread](./NTDLL/NtImpersonateThread/)
- [NtLoadDriver](./NTDLL/NtLoadDriver/)
- [NtMapViewOfSection](./NTDLL/NtMapViewOfSection/)
- `NtOpenFile`
- `NtOpenThread`
- [NtProtectVirtualMemory](./NTDLL/NtProtectVirtualMemory/)
- [NtQueueApcThread](./NTDLL/NtQueueApcThread/)
- `NtQueryInformationProcess`
- `NtRaiseHardError`
- `NtReadVirtualMemory`
- `NtResumeThread`
- `NtSetDebugFilterState`
- `NtSetInformationFile`
- `NtSetInformationProcess`
- [NtSetInformationThread](./NTDLL/NtSetInformationThread/)
- `NtSetInformationToken`
- `NtTraceEvent`
- `NtUnmapViewOfSection`
- [NtWriteVirtualMemory](./NTDLL/NtWriteVirtualMemory/)
- `RtlCreateUserThread`
- `SetThreadContext` / `GetThreadContext`
- `Wow64DisableWow64FsRedirection`

## PSAPI.DLL
- [EnumProcessModules](./PSAPI/EnumProcessModules/)

## WNET.DLL
- `WNetEnumResource`
