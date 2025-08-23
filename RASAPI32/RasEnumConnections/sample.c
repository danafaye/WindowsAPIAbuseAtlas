#include <windows.h>
#include <stdio.h>
#include <ras.h>
#include <raserror.h>

int main(void) {
    DWORD dwSize = sizeof(RASCONN);
    DWORD dwConnections = 0;
    DWORD dwRet;

    // Allocate buffer for connections
    RASCONN *lpRasConn = (RASCONN *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (lpRasConn == NULL) {
        printf("Failed to allocate memory.\n");
        return 1;
    }

    // Must set dwSize of first structure in array
    lpRasConn[0].dwSize = sizeof(RASCONN);

    // First call to RasEnumConnections
    dwRet = RasEnumConnections(lpRasConn, &dwSize, &dwConnections);

    if (dwRet == ERROR_BUFFER_TOO_SMALL) {
        // Reallocate to required size
        HeapFree(GetProcessHeap(), 0, lpRasConn);
        lpRasConn = (RASCONN *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
        if (lpRasConn == NULL) {
            printf("Failed to allocate memory.\n");
            return 1;
        }
        lpRasConn[0].dwSize = sizeof(RASCONN);

        dwRet = RasEnumConnections(lpRasConn, &dwSize, &dwConnections);
    }

    if (dwRet != ERROR_SUCCESS) {
        printf("RasEnumConnections failed with error %lu\n", dwRet);
        if (dwRet == ERROR_INVALID_HANDLE) {
            printf("ERROR_INVALID_HANDLE: No RAS connections found.\n");
        }
        HeapFree(GetProcessHeap(), 0, lpRasConn);
        return 1;
    }

    if (dwConnections == 0) {
        printf("No active RAS connections found.\n");
    } else {
        printf("Active RAS Connections: %lu\n\n", dwConnections);
        for (DWORD i = 0; i < dwConnections; i++) {
            printf("Connection %lu:\n", i + 1);
            printf("  Entry Name : %ws\n", lpRasConn[i].szEntryName);
            printf("  Device Name: %ws\n", lpRasConn[i].szDeviceName);
            printf("  Device Type: %ws\n", lpRasConn[i].szDeviceType);
            printf("  Handle     : %p\n\n", lpRasConn[i].hrasconn);
        }
    }

    // Clean up
    HeapFree(GetProcessHeap(), 0, lpRasConn);
    return 0;
}

// define WinMain so the linker stops complaining
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
    return main();
}