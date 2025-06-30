#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

int main() {
    DWORD index = 0;
    DWORD provType = 0;
    CHAR provName[256];
    DWORD provNameLen = sizeof(provName);
    HCRYPTPROV hProv = 0;

    printf("Enumerating Cryptographic Providers:\n\n");

    while (CryptEnumProvidersA(index, NULL, 0, &provType, provName, &provNameLen)) {
        printf("Provider %d: %s (Type %lu)\n", index, provName, provType);

        // Attempt to acquire a context
        if (CryptAcquireContextA(&hProv, NULL, provName, provType, CRYPT_VERIFYCONTEXT)) {
            printf("  [*] Acquired context for %s\n", provName);

            // Normally here you'd call CryptGetUserKey or CryptExportKey to exfil keys
            CryptReleaseContext(hProv, 0);
        } else {
            printf("  [!] Failed to acquire context (Error: %lu)\n", GetLastError());
        }

        index++;
        provNameLen = sizeof(provName); // reset buffer size
    }

    if (GetLastError() == ERROR_NO_MORE_ITEMS) {
        printf("\nEnumeration complete.\n");
    } else {
        printf("\nEnumeration failed. Error: %lu\n", GetLastError());
    }

    return 0;
}
