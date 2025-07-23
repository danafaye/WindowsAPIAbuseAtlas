#include <windows.h> // Required for Windows API functions
#include <tlhelp32.h> // Required for Tool Help Library functions (CreateToolhelp32Snapshot, PROCESSENTRY32, etc.)
#include <stdio.h>   // Required for standard input/output operations (printf)

// Main function of the program
int main() {
    // Declare a handle for the snapshot.
    // This handle will be used to refer to the captured system state.
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    // Check if the snapshot was created successfully.
    // INVALID_HANDLE_VALUE indicates an error.
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Error: Could not create process snapshot. Error Code: %lu\n", GetLastError());
        return 1; // Return with an error code
    }

    // Declare a PROCESSENTRY32 structure.
    // This structure will hold information about each process.
    PROCESSENTRY32 pe32;

    // IMPORTANT: Before using PROCESSENTRY32, you must set its dwSize member
    // to the size of the structure. If you don't, Process32First/Next will fail.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process encountered in the snapshot.
    // If this fails, it means there are no processes or an error occurred.
    if (!Process32First(hSnapshot, &pe32)) {
        printf("Error: Could not retrieve information about the first process. Error Code: %lu\n", GetLastError());
        CloseHandle(hSnapshot); // Always close the handle if an error occurs
        return 1;
    }

    // Print a header for the output
    printf("Process List:\n");
    printf("-----------------------------------------------------------------\n");
    printf("%-8s %-8s %s\n", "PID", "PPID", "Process Name");
    printf("-----------------------------------------------------------------\n");

    // Loop through all processes in the snapshot
    do {
        // Print the Process ID, Parent Process ID, and the executable file name.
        // The szExeFile member is a null-terminated string containing the executable name.
        printf("%-8lu %-8lu %s\n", pe32.th32ProcessID, pe32.th32ParentProcessID, pe32.szExeFile);
    } while (Process32Next(hSnapshot, &pe32)); // Continue as long as there are more processes

    // Close the snapshot handle.
    // It's crucial to close handles to release system resources.
    CloseHandle(hSnapshot);

    printf("-----------------------------------------------------------------\n");
    printf("Process enumeration complete.\n");

    return 0; // Return successfully
}
