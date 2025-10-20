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
- [DuplicateTokenEx](./ADVAPI32/DuplicateTokenEx/)
- [ImpersonateLoggedOnUser](./ADVAPI32/ImpersonateLoggedOnUser/)
- [LsaOpenPolicy](./ADVAPI32/LsaOpenPolicy/)
- [LsaRetrievePrivateData](./ADVAPI32/LsaRetrievePrivateData/)
- [OpenProcessToken](./ADVAPI32/OpenProcessToken/)
- [OpenSCManager](./ADVAPI32/OpenSCManager/)
- `QueryServiceStatusEx`
- [RegCreateKeyEx](./ADVAPI32/RegSetValueEx/)
- [RegEnumKeyEx](./ADVAPI32/RegEnumKeyEx/)
- [RegSetValueEx](./ADVAPI32/RegSetValueEx/)

# AMSI.DLL
- `AmsiInitialize`
- `AmsiOpenSession`
- [AmsiScanBuffer](./AMSI/AmsiScanBuffer/)
- [AmsiScanString](./AMSI/AmsiScanString/)

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
- [CreateEvent](./KERNEL32/CreateEvent/)
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
- [GetSystemFirmwareTable](./KERNEL32/GetSystemFirmwareTable/)
- [LoadLibrary](./KERNEL32/LoadLibrary/)
- `MapViewOfFile` + `LoadLibraryA/W`
- [PssCaptureSnapshot](./KERNEL32/PssCaptureSnapshot/)
- `QueueUserAPC`
- [SetDllDirectory](./KERNEL32/SetDllDirectory/)
- `SetProcessMitigationPolicy`
- [SetSearchPathMode](./KERNEL32/SetSearchPathMode/)
- [SetThreadContext](./KERNEL32/SetThreadContext/)
- [UpdateProcThreadAttribute](./KERNEL32/UpdateProcThreadAttribute/)
- [VirtualAllocEx](./KERNEL32/VirtualAllocEx/)
- [VirtualProtectEx](./KERNEL32/VirtualProtectEx/)
- [WriteProcessMemory](./KERNEL32/WriteProcessMemory/)
- [WriteProfileString](./KERNEL32/WriteProfileString/)

## MPR.DLL
- [WNetAddConnection2](./MPR/WNetAddConnection2/)

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
- [NtAllocateVirtualMemory](./NTDLL/NtAllocateVirtualMemory/)
- `NtAlertResumeThread`
- [NtAlpcConnectPort](./NTDLL/NtAlpcConnectPort/)
- [NtCreateFile](./NTDLL/NtCreateFile/)
- [NtCreateKey](./NTDLL/NtCreateKey/)
- [NtCreateSection](./NTDLL/NtCreateSection/)
- [NtCreateThreadEx](./NTDLL/NtCreateThreadEx/)
- [NtDeviceIoControlFile](./NTDLL/NtDeviceIoControlFile/)
- [NtImpersonateThread](./NTDLL/NtImpersonateThread/)
- [NtLoadDriver](./NTDLL/NtLoadDriver/)
- [NtMapViewOfSection](./NTDLL/NtMapViewOfSection/)
- `NtOpenFile`
- [NtOpenProcessToken](./NTDLL/NtOpenProcessToken/)
- `NtOpenThread`
- [NtProtectVirtualMemory](./NTDLL/NtProtectVirtualMemory/)
- [NtQueueApcThread](./NTDLL/NtQueueApcThread/)
- [NtQueryInformationProcess](./NTDLL/NtQueryInformationProcess/)
- [NtQuerySystemInformation](./NTDLL/NtQuerySystemInformation/)
- [NtQueryVirtualMemory](./NTDLL/NtQueryVirtualMemory/)
- [NtRaiseHardError](./NTDLL/NtRaiseHardError)
- [NtReadVirtualMemory](./NTDLL/NtReadVirtualMeemory/)
- `NtResumeThread`
- `NtSetDebugFilterState`
- `NtSetInformationFile`
- [NtSetInformationProcess](./NTDLL/NtSetInformationProcess/)
- [NtSetInformationThread](./NTDLL/NtSetInformationThread/)
- `NtSetInformationToken`
- [NtSuspendProcess](./NTDLL/NtSuspendProcess/)
- [NtSystemDebugControl](./NTDLL/NtSystemDebugControl/)
- [NtTraceEvent](./NTDLL/NtTraceEvent/)
- [NtUnmapViewOfSection](./NTDLL/NtUnmapViewOfSection)
- [NtWriteVirtualMemory](./NTDLL/NtWriteVirtualMemory/)
- [RtlCreateUserProcess](./NTDLL/RtlCreateUserProcess/)
- [RtlCreateUserThread](./NTDLL/RtlCreateUserThread/)
- `SetThreadContext` / `GetThreadContext`
- [Wow64DisableWow64FsRedirection](./NTDLL/Wow64DisableWow64FsRedirection/)
- [ZwQuerySystemInformationEx](./NTDLL/ZwQuerySystemInformationEx)
- [ZwUnmapViewOfSection](./NTDLL/ZwUnmapViewOfSection/)

## OLE32.DLL
- [CoCreateInstance](./OLE32/CoCreateInstance/)
- [CoCreateInstanceEx](./OLE32/CoCreateInstanceEx/)
- [CoGetClassObject](./OLE32/CoGetClassObject/)
- `CoSetProxyBlanket`

## PSAPI.DLL
- [EnumProcessModules](./PSAPI/EnumProcessModules/)
- [GetModuleFileNameEx](./PSAPI/GetModuleFileNameEx/)
- `GetModuleInformation`
- `GetProcessMemoryInfo`

## RASAPI32.DLL
- [RasEnumConnections](./RASAPI32/RasEnumConnections/)
- `RasGetEntryDialParams`
- `RasGetEntryProperties`

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

## URLMON.DLL
- [URLDownloadToFile](./URLMON/URLDownloadToFile/)

## USER32.DLL
- [LockWorkStation](./USER32/LockWorkStation/)
- [Open Desktop](./USER32/OpenDesktop/)
- [SetClipboardData](./USER32/SetClipboardData/)
- [SetWindowsHookEx](./USER32/SetWindowsHookEx/)

## WINHTTP.DLL
- [WinHttpConnect](./WINHTTP/WinHttpConnect/)

## WINSTA.DLL
- [WinStationQueryInformationW](./WINSTA/WinStationQueryInformationW/)

