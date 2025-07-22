#include <windows.h>
#include <stdio.h>

// These constants define the type of ETW provider notifications we can receive.
// They are not officially documented in the Windows SDK.
#define EtwNotificationTypeNoOp             0x00 // Not strictly a "type" but used for general registration
#define EtwNotificationProviderRegistered   0x01
#define EtwNotificationProviderUnregistered 0x02
#define EtwNotificationProviderUpdated      0x03


// Typedef for the callback function signature.
// This function is called by the system when a provider registers/unregisters/updates.
typedef ULONG (__fastcall *ETW_NOTIFICATION_CALLBACK)(
    ULONG NotificationType, // EtwNotificationProviderRegistered, etc.
    LPCGUID SourceId,       // GUID of the provider
    ULONG NotificationSize, // Size of the Notification data
    PVOID Notification      // Pointer to the notification data (depends on NotificationType)
);

// Typedef for the EtwNotificationRegister function.
// Registers the callback to receive ETW provider notifications.
// IMPORTANT: This function expects 4 arguments based on common reverse engineering.
typedef NTSTATUS (__fastcall *ETW_NOTIFICATION_REGISTER)(
    LPCGUID Guid,                     // Specific provider GUID, or NULL for all (provider registration events)
    ETW_NOTIFICATION_CALLBACK Callback, // Pointer to your callback function
    PVOID Context,                    // User-defined context (optional)
    PVOID* RegistrationHandle         // Returned handle for unregistration
);

// Typedef for the EtwNotificationUnregister function.
typedef NTSTATUS (__fastcall *ETW_NOTIFICATION_UNREGISTER)(
    PVOID RegistrationHandle
);

// This is our callback function.
// It will be invoked when new ETW providers are registered on the system.
ULONG NTAPI EtwNotificationCallback(
    ULONG NotificationType,
    LPCGUID ProviderId,
    ULONG NotificationSize,
    PVOID Notification
) {
    // Print the type of notification received
    wprintf(L"[+] Notification Type: 0x%X\n", NotificationType);

    // If it's a provider registration event, print a message
    if (NotificationType == EtwNotificationProviderRegistered) {
        // Convert GUID to string for printing
        WCHAR guidString[40];
        if (StringFromGUID2(ProviderId, guidString, RTL_NUMBER_OF_V2(guidString))) {
            wprintf(L"    → New provider registered. GUID: %s\n", guidString);
        } else {
            wprintf(L"    → New provider registered. (Failed to convert GUID)\n");
        }
        
        // In a real abuse scenario, this is where malware could:
        // - Check the ProviderId against known security tools (e.g., AV/EDR GUIDs)
        // - Record or react to the presence of logging frameworks
    }

    return 0; // Return STATUS_SUCCESS
}

// Ensure you remove your manual GUID struct definition if it's still there
const GUID MICROSOFT_WINDOWS_KERNEL_PROCESS_GUID = { 0x22fb2cd6, 0x0e7b, 0x4261, { 0x8c, 0x56, 0x11, 0x88, 0x4c, 0x0f, 0x22, 0x31 } };

int main() { // This is the opening brace for main()
    // Declare RegistrationHandle here
    PVOID RegistrationHandle = NULL; 

    // Load ntdll.dll manually to resolve undocumented functions
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to load ntdll.dll\n");
        return 1;
    }

    // Dynamically resolve the EtwNotificationRegister function
    ETW_NOTIFICATION_REGISTER EtwNotificationRegister = 
        (ETW_NOTIFICATION_REGISTER)GetProcAddress(hNtdll, "EtwNotificationRegister");

    // Dynamically resolve the EtwNotificationUnregister function
    ETW_NOTIFICATION_UNREGISTER EtwNotificationUnregister = 
        (ETW_NOTIFICATION_UNREGISTER)GetProcAddress(hNtdll, "EtwNotificationUnregister");

    // Ensure both function pointers were resolved
    if (!EtwNotificationRegister || !EtwNotificationUnregister) {
        printf("[-] Failed to resolve EtwNotificationRegister/Unregister\n");
        return 1;
    }

    // Register to receive notifications from all ETW providers (NULL GUID)
    // NOTE: The first parameter is the GUID. For notifications about provider registration/unregistration,
    // NULL is used here to indicate "all providers". The "type" of notification is handled by the callback itself.
    NTSTATUS status = EtwNotificationRegister(
        &MICROSOFT_WINDOWS_KERNEL_PROCESS_GUID, // Pass a pointer to a specific GUID
        EtwNotificationCallback,
        NULL,
        &RegistrationHandle
    );

    if (status != 0) {
        printf("[-] EtwNotificationRegister failed: 0x%lx\n", status);
        // It's common for this to fail with 0xC0000022 (STATUS_ACCESS_DENIED) if not elevated.
        // Or 0xC000000D (STATUS_INVALID_PARAMETER) if the signature is wrong.
        return 1;
    }

    printf("[+] Successfully registered for ETW provider notifications\n");
    printf("    Press Enter to exit...\n");

    // Wait for user input while notifications may come in
    getchar();

    // Unregister the callback before exiting
    if (RegistrationHandle != NULL) { // Only unregister if registration succeeded
        EtwNotificationUnregister(RegistrationHandle);
        printf("[+] Unregistered\n");
    } else {
        printf("[-] No registration handle to unregister.\n");
    }

    return 0;
} // This is the new closing brace for main()