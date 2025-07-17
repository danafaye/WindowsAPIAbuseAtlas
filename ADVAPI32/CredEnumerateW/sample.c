#include <windows.h> 
#include <wincred.h> 
#include <stdio.h>   
#include <locale.h>  
#include <io.h>      
#include <fcntl.h>

int main() {
    // Set console output mode to UTF-16 (Unicode)
    if (_setmode(_fileno(stdout), _O_U16TEXT) == -1) {
        // Attempts to set the locale based on user's environment
        setlocale(LC_ALL, ""); // Attempt to set locale from environment
    }

    PCREDENTIALW *creds = NULL;
    DWORD count = 0;

    // CredEnumerateW enumerates credentials.
    // The second parameter (Flags) should be 0 for common enumeration.
    if (CredEnumerateW(NULL, 0, &count, &creds)) {
        wprintf(L"Found %lu credentials:\n\n", count); 

        for (DWORD i = 0; i < count; i++) {
            wprintf(L"  TargetName: %s\n", creds[i]->TargetName); 
            wprintf(L"  UserName:   %s\n", creds[i]->UserName); 

            if (creds[i]->CredentialBlobSize > 0) {
                if (creds[i]->CredentialBlobSize % sizeof(wchar_t) == 0) {
                    wprintf(L"  Password:   %s\n", (wchar_t*)creds[i]->CredentialBlob);
                } else {
                    wprintf(L"  Password (raw bytes, size %lu): ", creds[i]->CredentialBlobSize);
                    for (DWORD j = 0; j < creds[i]->CredentialBlobSize; j++) {
                        wprintf(L"%02X ", creds[i]->CredentialBlob[j]); 
                    }
                    wprintf(L"\n");
                }
            } else {
                wprintf(L"  Password:   (none/empty)\n");
            }
            wprintf(L"\n");
        }
        CredFree(creds);
    } else {
        // Didn't work
        wprintf(L"CredEnumerateW failed. Error code: %lu\n", GetLastError());
    }
    return 0;
}