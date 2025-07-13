#include <windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include <initguid.h>

// Dummy callout GUID (replace with your real one)
DEFINE_GUID(
    CALLOUT_GUID,
    0xaabbccdd, 0xeeff, 0x1122, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00
);

int main()
{
    DWORD result;
    HANDLE engineHandle = NULL;

    // Open a session to the filtering engine
    result = FwpmEngineOpen0(
        NULL,                // local system
        RPC_C_AUTHN_WINNT,   // authentication service
        NULL,                // auth identity
        NULL,                // session
        &engineHandle
    );
    if (result != ERROR_SUCCESS) {
        printf("FwpmEngineOpen0 failed: %lu\n", result);
        return 1;
    }
    printf("WFP engine opened successfully.\n");

    // Prepare filter conditions
    FWPM_FILTER_CONDITION0 condition = {0};
    condition.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_UINT16;
    condition.conditionValue.uint16 = 21; // FTP port

    // Prepare the filter structure
    FWPM_FILTER0 filter = {0};
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.displayData.name = L"FTP Filter - Redirect Placeholder";
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING; // Requires a callout
    filter.action.calloutKey = CALLOUT_GUID;
    filter.filterCondition = &condition;
    filter.numFilterConditions = 1;
    filter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;  // Built-in universal sublayer
    filter.weight.type = FWP_EMPTY; // Default weight

    // Add the filter
    result = FwpmFilterAdd0(engineHandle, &filter, NULL, NULL);
    if (result != ERROR_SUCCESS) {
        printf("FwpmFilterAdd0 failed: %lu\n", result);
        FwpmEngineClose0(engineHandle);
        return 1;
    }
    printf("FTP filter added successfully.\n");

    // Close the filtering engine handle
    FwpmEngineClose0(engineHandle);
    printf("WFP engine closed.\n");

    return 0;
}
