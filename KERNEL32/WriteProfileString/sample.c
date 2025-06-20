#include <windows.h>
#include <stdio.h>

int main() {
    LPCSTR section = "Loader";
    LPCSTR key = "Payload";
    LPCSTR value = "TVqQAAMAAAAEAAAA"; // could be base64 payload
    LPCSTR iniPath = "C:\\Users\\Public\\loader.ini";

    BOOL result = WriteProfileStringA(section, key, value);

    // Optional: also write to a custom .ini file path
    // This version writes to a non-default INI file using kernel32's WritePrivateProfileString
    BOOL result2 = WritePrivateProfileStringA(section, key, value, iniPath);

    if (result && result2) {
        printf("Successfully wrote to INI file.\n");
    } else {
        printf("Failed to write. Error code: %lu\n", GetLastError());
    }

    return 0;
}
