#include <windows.h>
#include <stdio.h>

void getFirmwareTable(const char* providerName)
{
    DWORD provider = *(DWORD*)providerName; // Convert 4-char string to DWORD
    DWORD bufferSize = GetSystemFirmwareTable(provider, 0, NULL, 0);

    if (bufferSize == 0)
    {
        printf("[%s] No data or failed to get size. Error: %lu\n", providerName, GetLastError());
        return;
    }

    BYTE* buffer = (BYTE*)malloc(bufferSize);
    if (!buffer)
    {
        printf("Failed to allocate buffer.\n");
        return;
    }

    DWORD retSize = GetSystemFirmwareTable(provider, 0, buffer, bufferSize);
    if (retSize == 0)
    {
        printf("[%s] Failed to get firmware table. Error: %lu\n", providerName, GetLastError());
    }
    else
    {
        printf("[%s] Retrieved firmware table. Size: %lu bytes\n", providerName, retSize);
    }

    free(buffer);
}

int main()
{
    printf("=== GetSystemFirmwareTable Demo ===\n");

    getFirmwareTable("ACPI"); // ACPI table
    getFirmwareTable("RSMB"); // Raw SMBIOS table

    return 0;
}
