# Windows API Abuse Atlas
WindowsAPIAbuseAtlas is an evolving map of the sneaky and lesser-known ways malware twists Windows APIs to hide, evade, and attack. It’s packed with practical reverse engineering insights, ready-to-use YARA rules, and clear behavioral clues that help defenders spot these tricks in the wild. Whether you’re hunting threats, building detections, or just curious about how bad actors operate behind the scenes, this atlas sheds light on complex Windows behavior ... empowering the cyber community to stay one step ahead.

# Index
This is a living roadmap. As I knock out each entry, I’ll link it here, and I might add new ones along the way. If you don’t see a link yet, it’s either a placeholder for something I plan to write, or just an API that’s on the radar.


## ADVAPI32.DLL
- [AdjustTokenPrivileges](./ADVAPI32/AdjustTokenPrivileges/)
- `ChangeServiceConfig2`
- [ControlService](./ADVAPI32/ControlService/)
- `CreateService`
- `CredEnumerateW`
- `CredReadW`
- [CryptEnumProviders](./ADVAPI32/CryptEnumProviders/)
- `DuplicateTokenEx`
- `ImpersonateLoggedOnUser`
- `LsaOpenPolicy`
- [LsaRetrievePrivateData](./ADVAPI32/LsaRetrievePrivateData/)
- `OpenProcessToken`
- `OpenSCManager`
- `QueryServiceStatusEx`
- [RegCreateKeyEx](./ADVAPI32/RegSetValueEx/)
- [RegSetValueEx](./ADVAPI32/RegSetValueEx/)

## FWPUCLNT.DLL
- `FwpmCalloutAdd`
- `FwpmCalloutRegister`
- `FwpmEngineOpen`
- `FwpmFilterAdd`
- `FwpIpsecRoutine0`

## KERNEL32.DLL
- [ConvertThreadToFiber](./KERNEL32/ConvertThreadToFiber/)
- `CreateFiber`
- `CreateProcessAsUserW`
- `CreateProcessInternalW`
- `CreateProcessWithTokenW`
- [CreateRemoteThread](./KERNEL32/CreateRemoteThread/)
- [EnumSystemLocalesW](./KERNEL32/EnumSystemLocalesW/)
- `LoadLibraryA/W`
- `MapViewOfFile` + `LoadLibraryA/W`
- `PssCaptureSnapshot`
- `QueueUserAPC`
- `SetDllDirectoryA/W` + `LoadLibrary`
- `SetProcessMitigationPolicy`
- [SetThreadContext](./KERNEL32/SetThreadContext/)
- [UpdateProcThreadAttribute](./KERNEL32/UpdateProcThreadAttribute/)
- [VirtualAllocEx](./KERNEL32/VirtualAllocEx/)
- [WriteProcessMemory](./KERNEL32/WriteProcessMemory/)
- [WriteProfileString](./KERNEL32/WriteProfileString/)

## NETAPI32.DLL
- [NetLocalGroupGetMembers](./NETAPI32/NetLocalGroupGetMembers/)
- [NetRemoteTOD](./NETAPI32/NetRemoteTOD/)
- `NetSessionEnum`
- [NetUserAdd](./NETAPI32/NetUserAdd/)
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
- [NtQueryInformationProcess](./NTDLL/NtQueryInformationProcess/)
- `NtRaiseHardError`
- `NtReadVirtualMemory`
- `NtResumeThread`
- `NtSetDebugFilterState`
- `NtSetInformationFile`
- `NtSetInformationProcess`
- [NtSetInformationThread](./NTDLL/NtSetInformationThread/)
- `NtSetInformationToken`
- [NtTraceEvent](./NTDLL/NtTraceEvent/)
- `NtUnmapViewOfSection`
- [NtWriteVirtualMemory](./NTDLL/NtWriteVirtualMemory/)
- `RtlCreateUserThread`
- `SetThreadContext` / `GetThreadContext`
- [Wow64DisableWow64FsRedirection](./NTDLL/Wow64DisableWow64FsRedirection/)
- [ZwQuerySystemInformationEx](./NTDLL/ZwQuerySystemInformationEx)

## PSAPI.DLL
- [EnumProcessModules](./PSAPI/EnumProcessModules/)
- `GetModuleInformation`
- `GetProcessMemoryInfo`

## SETUPAPI.DLL
- [InstallHinfSection](./SETUPAPI/InstallHinfSection/)
- `SetupCopyOEMInf`
- `SetupDiGetClassDevs`
- `SetupDiEnumClassDeviceInfo`
- `SetupInstallFile`
- `SetupUninstallOEMInf`

## USER32.DLL
- [LockWorkStation](./USER32/LockWorkStation/)
- [SetWindowsHookEx](./USER32/SetWindowsHookEx/)

