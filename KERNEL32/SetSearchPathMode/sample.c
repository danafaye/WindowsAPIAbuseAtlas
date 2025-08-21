#include <windows.h>
#include <stdio.h>

#ifndef BASE_SEARCH_PATH_PER_USER_ENABLE
#define BASE_SEARCH_PATH_PER_USER_ENABLE 0x00000004
#endif

// To use this you'll need to create a test DLL named "testdll.dll"
// and place it in the current working directory. 
// The DLL should export a function to verify it loaded correctly.

int main() {

    // 1. Call without enabling per-user paths
    printf("[*] Trying to load testdll.dll without per-user paths...\n");
    HMODULE h1 = LoadLibraryA("testdll.dll");
    if (h1 == NULL) {
        printf("[-] Failed to load DLL (expected if not in app/System32).\n");
    } else {
        printf("[+] Loaded DLL from: testdll.dll\n");
        FreeLibrary(h1);
    }

    // 2. Enable per-user search paths
    if (!SetSearchPathMode(BASE_SEARCH_PATH_PER_USER_ENABLE)) {
        printf("[-] Failed to enable per-user search mode. Error: %lu\n", GetLastError());
        return 1;
    }
    printf("[*] Enabled BASE_SEARCH_PATH_PER_USER_ENABLE.\n");

    // 3. Try loading again (now per-user DLL dirs are included)
    printf("[*] Trying to load testdll.dll with per-user paths enabled...\n");
    HMODULE h2 = LoadLibraryA("testdll.dll");
    if (h2 == NULL) {
        printf("[-] Still failed to load DLL. Did you add it to a per-user directory?\n");
    } else {
        printf("[+] Loaded DLL from per-user directory!\n");
        FreeLibrary(h2);
    }

    return 0;
}

// WinMain wrapper to satisfy the linker
#ifdef _WIN32
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    return main();
}
#endif