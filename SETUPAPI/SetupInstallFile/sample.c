#include <windows.h>
#include <setupapi.h>
#include <stdio.h>

#pragma comment(lib, "setupapi.lib")

int main(void) {
    HINF hInf = SetupOpenInfFileA("C:\\Temp\\test.inf", NULL, INF_STYLE_WIN4, NULL);
    if (hInf == INVALID_HANDLE_VALUE) {
        printf("Failed to open INF file. Error: %lu\n", GetLastError());
        return 1;
    }

    INFCONTEXT context;
    if (!SetupFindFirstLineA(hInf, "DestinationDirs", "MyDriverFiles", &context)) {
        printf("Failed to find INF context. Error: %lu\n", GetLastError());
        SetupCloseInfFile(hInf);
        return 1;
    }

    BOOL result = SetupInstallFileA(
        hInf,
        &context,
        "C:\\Temp\\test_driver_note.txt", // Source file
        NULL,                             // Source path root
        "test_driver_note.txt",           // Destination name
        SP_COPY_NOOVERWRITE,
        NULL,
        NULL
    );

    if (result) {
        printf("File installed successfully.\n");
    } else {
        printf("SetupInstallFile failed. Error: %lu\n", GetLastError());
    }

    SetupCloseInfFile(hInf);
    return 0;
}
