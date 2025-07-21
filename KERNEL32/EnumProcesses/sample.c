#include <windows.h>
#include <psapi.h>
#include <stdio.h>

int main() {
    DWORD processIds[1024], bytesReturned;
    unsigned int i, numProcs;

    if (!EnumProcesses(processIds, sizeof(processIds), &bytesReturned)) {
        printf("EnumProcesses failed. Error: %lu\n", GetLastError());
        return 1;
    }

    numProcs = bytesReturned / sizeof(DWORD);
    printf("Found %u running processes:\n", numProcs);

    for (i = 0; i < numProcs; i++) {
        printf("PID: %lu\n", processIds[i]);
    }

    return 0;
}
