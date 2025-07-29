#include <windows.h>
#include <stdio.h>

int main() {
    HANDLE hTransaction = CreateTransaction(NULL, 0, 0, 0, 0, 0, NULL);
    if (hTransaction == INVALID_HANDLE_VALUE) {
        printf("Failed to create transaction. Error: %lu\n", GetLastError());
        return 1;
    }

    HANDLE hFile = CreateFileTransactedA(
        "C:\\Temp\\stealthy.txt",          // File path
        GENERIC_WRITE,                     // Desired access
        0,                                // Share mode
        NULL,                             // Security attributes
        CREATE_ALWAYS,                    // Creation disposition
        FILE_ATTRIBUTE_NORMAL,            // Flags and attributes
        NULL,                             // Template file
        hTransaction,                     // Transaction handle
        NULL,                             // Reserved
        NULL                              // Extended parameters
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to create transacted file. Error: %lu\n", GetLastError());
        CloseHandle(hTransaction);
        return 1;
    }

    const char *data = "This file is created inside a transaction.\n";
    DWORD bytesWritten;
    WriteFile(hFile, data, (DWORD)strlen(data), &bytesWritten, NULL);

    // Uncomment this to commit the transaction (make changes permanent)
    // if (!CommitTransaction(hTransaction)) {
    //     printf("Failed to commit transaction. Error: %lu\n", GetLastError());
    // }

    // Uncomment this to rollback the transaction (discard changes)
    if (!RollbackTransaction(hTransaction)) {
        printf("Failed to rollback transaction. Error: %lu\n", GetLastError());
    }

    CloseHandle(hFile);
    CloseHandle(hTransaction);

    printf("Transaction complete. File changes %s.\n",
           /*(committed ? "committed" : "rolled back")*/ "rolled back");

    return 0;
}
