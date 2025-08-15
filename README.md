<img style="float:right" src="atlas.png" width="35%"/>

# Windows API Abuse Atlas
WindowsAPIAbuseAtlas is an evolving map of the sneaky and lesser-known ways malware twists Windows APIs to hide, evade, and attack. It’s packed with practical reverse engineering insights, ready-to-use YARA rules, and clear behavioral clues that help defenders spot these tricks in the wild. Whether you’re hunting threats, building detections, or just curious about how bad actors operate behind the scenes, this atlas sheds light on complex Windows behavior ... empowering the cyber community to stay one step ahead.

# Index
This is a living roadmap. As I knock out each entry, I’ll link it here, and I might add new ones along the way. If you don’t see a link yet, it’s either a placeholder for something I plan to write, or just an API that’s on the radar.


## ADVAPI32.DLL
- [AdjustTokenPrivileges](./ADVAPI32/AdjustTokenPrivileges/)
- `ChangeServiceConfig2`
- [ControlService](./ADVAPI32/ControlService/)
- [CreateProcessAsUserW](./ADVAPI32/CreateProcessAsUser/)
- [CreateProcessWithTokenW](./ADVAPI32/CreateProcessWithTokenW/)
- `CreateService`
- [CredEnumerateW](./ADVAPI32/CredEnumerateW/)
- `CredReadW`
- [CryptEnumProviders](./ADVAPI32/CryptEnumProviders/)
- `DuplicateTokenEx`
- `ImpersonateLoggedOnUser`
- `LsaOpenPolicy`
- [LsaRetrievePrivateData](./ADVAPI32/LsaRetrievePrivateData/)
- [OpenProcessToken](./ADVAPI32/OpenProcessToken/)
- [OpenSCManager](./ADVAPI32/OpenSCManager/)
- `QueryServiceStatusEx`
- [RegCreateKeyEx](./ADVAPI32/RegSetValueEx/)
- [RegSetValueEx](./ADVAPI32/RegSetValueEx/)

# AMSI.DLL
- `AmsiInitialize`
- `AmsiOpenSession`
- [AmsiScanBuffer](./AMSI/AmsiScanBuffer/)
- `AmsiScanString`

# DNSAPI.DLL
- [DnsQuery](./DNSAPI/DnsQuery/)

## FWPUCLNT.DLL
- `FwpmCalloutAdd`
- `FwpmCalloutRegister`
- [FwpmEngineOpen](./FWPUCLNT/FwpmEngineOpen/)
- `FwpmFilterAdd`
- `FwpIpsecRoutine0`

## KERNEL32.DLL
- [ConvertThreadToFiber](./KERNEL32/ConvertThreadToFiber/)
- `CreateFiber`
- `CreateFile`
- [CreateFileMapping](./KERNEL32/CreateFileMapping/)
- [CreateFileTransacted](./KERNEL32/CreateFileTransacted/)
- [CreateNamedPipe](./KERNEL32/CreateNamedPipe/)
- `CreateProcessInternalW`
- [CreateRemoteThread](./KERNEL32/CreateRemoteThread/)
- [CreateToolhelp32Snapshot](./KERNEL32/CreateToolhelp32Snapshot/)
- [EnumProcesses](./KERNEL32/EnumProcesses/)
- [EnumSystemLocalesW](./KERNEL32/EnumSystemLocalesW/)
- `LoadLibraryA/W`
- `MapViewOfFile` + `LoadLibraryA/W`
- [PssCaptureSnapshot](./KERNEL32/PssCaptureSnapshot/)
- `QueueUserAPC`
- `SetDllDirectoryA/W` + `LoadLibrary`
- `SetProcessMitigationPolicy`
- [SetThreadContext](./KERNEL32/SetThreadContext/)
- [UpdateProcThreadAttribute](./KERNEL32/UpdateProcThreadAttribute/)
- [VirtualAllocEx](./KERNEL32/VirtualAllocEx/)
- [WriteProcessMemory](./KERNEL32/WriteProcessMemory/)
- [WriteProfileString](./KERNEL32/WriteProfileString/)

## NETAPI32.DLL
- [DsGetDcName](./NETAPI32/DsGetDcName/)
- [NetLocalGroupGetMembers](./NETAPI32/NetLocalGroupGetMembers/)
- [NetRemoteTOD](./NETAPI32/NetRemoteTOD/)
- `NetSessionEnum`
- [NetUserAdd](./NETAPI32/NetUserAdd/)
- `NetWkstaUserEnum`

## NTDLL.DLL
- [DbgUiRemoteBreakin](./NTDLL/DbgUiRemoteBreakin/)
- [EtwEventWrite](./NTDLL/EtwEventWrite/)
- [EtwNotificationRegister](./NTDLL/EtwNotificationRegister/)
- [EtwProviderEnabled](./NTDLL/EtwProviderEnabled/)
- [LdrGetProcedureAddress](./NTDLL/LdrGetProcedureAddress/)
- [LdrLoadDll](./NTDLL/LdrLoadDll/)
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
- [NtQueryVirtualMemory](./NTDLL/NtQueryVirtualMemory/)
- `NtRaiseHardError`
- `NtReadVirtualMemory`
- `NtResumeThread`
- `NtSetDebugFilterState`
- `NtSetInformationFile`
- `NtSetInformationProcess`
- [NtSetInformationThread](./NTDLL/NtSetInformationThread/)
- `NtSetInformationToken`
- [NtTraceEvent](./NTDLL/NtTraceEvent/)
- [NtUnmapViewOfSection](./NTDLL/NtUnmapViewOfSection)
- [NtWriteVirtualMemory](./NTDLL/NtWriteVirtualMemory/)
- [RtlCreateUserThread](./NTDLL/RtlCreateUserThread/)
- `SetThreadContext` / `GetThreadContext`
- [Wow64DisableWow64FsRedirection](./NTDLL/Wow64DisableWow64FsRedirection/)
- [ZwQuerySystemInformationEx](./NTDLL/ZwQuerySystemInformationEx)

## OLE32.DLL
- [CoCreateInstance](./OLE32/CoCreateInstance/)
- [CoCreateInstanceEx](./OLE32/CoCreateInstanceEx/)
- `CoGetClassObject`
- `CoSetProxyBlanket`

## PSAPI.DLL
- [EnumProcessModules](./PSAPI/EnumProcessModules/)
- [GetModuleFileNameEx](./PSAPI/GetModuleFileNameEx/)
- `GetModuleInformation`
- `GetProcessMemoryInfo`

## SETUPAPI.DLL
- [InstallHinfSection](./SETUPAPI/InstallHinfSection/)
- `SetupCopyOEMInf`
- `SetupDiGetClassDevs`
- `SetupDiEnumClassDeviceInfo`
- [SetupInstallFile](./SETUPAPI/SetupInstallFile/)
- `SetupUninstallOEMInf`

## SHELL32.DLL
- [ShellExecute](./SHELL32/ShellExecute/)
- [SHGetKnownFolderPath](./SHELL32/SHGetKnownFolderPath/)

## UIAUTOMATIONCORE
-  [AddAutomationEventHandler](./UIAUTOMATIONCORE/AddAutomationEventHandler/) 

## USER32.DLL
- [LockWorkStation](./USER32/LockWorkStation/)
- [Open Desktop](./USER32/OpenDesktop/)
- [SetClipboardData](./USER32/SetClipboardData/)
- [SetWindowsHookEx](./USER32/SetWindowsHookEx/)

## WINSTA.DLL
- [WinStationQueryInformationW](./WINSTA/WinStationQueryInformationW/)

