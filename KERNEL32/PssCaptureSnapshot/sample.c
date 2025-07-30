#include <windows.h>
#include <processthreadsapi.h>
#include <stdio.h>
#include <psapi.h>    // For PROCESS_QUERY_INFORMATION
#include <pdh.h>      // Process Snapshot API headers
#include <processsnapshot.h>   // For PssCaptureSnapshot and friends


#pragma comment(lib, "Pssapi.lib")

int main() {
    HANDLE snapshot = NULL;
    DWORD pid = GetCurrentProcessId();
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        printf("Failed to open process: %lu\n", GetLastError());
        return 1;
    }

    // Capture a snapshot of the current process
    HRESULT hPssCaptureSnapshot = PssCaptureSnapshot(
        hProcess,
        PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_HANDLES | PSS_CAPTURE_THREADS,
        CONTEXT_ALL,
        &snapshot
    );

    if (FAILED(hPssCaptureSnapshot)) {
        printf("PssCaptureSnapshot failed: 0x%lx\n", hPssCaptureSnapshot);
        CloseHandle(hProcess);
        return 1;
    }

    printf("Snapshot captured successfully.\n");

    // Normally you would query and walk the snapshot here
    // For this example, just free it immediately
    hPssCaptureSnapshot = PssFreeSnapshot(GetCurrentProcess(), snapshot);
    if (FAILED(hPssCaptureSnapshot)) {
        printf("PssFreeSnapshot failed: 0x%lx\n", hPssCaptureSnapshot);
    } else {
        printf("Snapshot freed successfully.\n");
    }

    CloseHandle(hProcess);
    return 0;
}
