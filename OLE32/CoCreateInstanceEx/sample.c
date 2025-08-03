#include <stdio.h>   // Added to fix the 'printf' implicit declaration warning/error
#include <windows.h>
#include <objbase.h> // For CoInitializeEx and CoUninitialize
#include <exdisp.h>  // For IWebBrowser2 and related GUIDs
#include <ole2.h>    // For OLE functions

// A simple helper macro for checking HRESULT values
#define CHECK_HR(hr, msg) \
    if (FAILED(hr)) { \
        printf(msg " failed with HRESULT: 0x%08lX\n", hr); \
        goto cleanup; \
    }

int main() {
    HRESULT hr;
    IWebBrowser2* pWebBrowser = NULL;

    // The CLSID for the WebBrowser control. This is a standard GUID.
    const CLSID CLSID_WebBrowser = {0x8856F961, 0x340A, 0x11D0, {0xA9, 0x6B, 0x00, 0xC0, 0x4F, 0xD7, 0x05, 0xA2}};

    // The IID for the IWebBrowser2 interface.
    const IID IID_IWebBrowser2 = {0xD30C1661, 0xC810, 0x11D2, {0x9F, 0x47, 0x00, 0xC0, 0x4F, 0x79, 0x6E, 0x3A}};

    // 1. Initialize the COM library. This must be done before any COM calls.
    // We use COINIT_APARTMENTTHREADED for UI-related objects.
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    CHECK_HR(hr, "CoInitializeEx");

    // 2. Set up the COSERVERINFO structure.
    // For this local example, we set pwszName to NULL.
    // For a remote machine, you would specify the machine's name here (e.g., L"\\server").
    COSERVERINFO serverInfo = {0};
    serverInfo.pwszName = NULL; // Instantiate on the local machine
    serverInfo.dwReserved1 = 0;
    serverInfo.dwReserved2 = 0;

    // 3. Set up the MULTI_QI array.
    // This structure specifies the interfaces we want to retrieve.
    // We only need one for this example: IWebBrowser2.
    MULTI_QI qi[1];
    qi[0].pIID = &IID_IWebBrowser2;
    qi[0].pItf = NULL; // Will be filled by CoCreateInstanceEx
    qi[0].hr = S_OK;

    // 4. Call CoCreateInstanceEx to create the object.
    // We pass the CLSID, server info, and our MULTI_QI array.
    printf("Attempting to create WebBrowser object locally...\n");
    hr = CoCreateInstanceEx(
        &CLSID_WebBrowser, // Corrected: Pass a pointer to the CLSID, not the CLSID itself
        NULL,             // Outer object for aggregation (not used here)
        CLSCTX_LOCAL_SERVER, // Context in which to run the code
        &serverInfo,      // Server information (local in this case)
        1,                // Number of interfaces to request
        qi                // The array of interfaces to request
    );

    // Check the overall return code for CoCreateInstanceEx
    CHECK_HR(hr, "CoCreateInstanceEx");

    // Check the HRESULT for the specific interface request
    hr = qi[0].hr;
    CHECK_HR(hr, "Failed to retrieve IWebBrowser2 interface");

    // The call was successful. Get the interface pointer.
    pWebBrowser = (IWebBrowser2*)qi[0].pItf;
    printf("Successfully created IWebBrowser2 object.\n");

    // 5. Use the object. For this example, we'll navigate to a URL.
    printf("Navigating to http://www.google.com...\n");
    hr = pWebBrowser->lpVtbl->Navigate(
        pWebBrowser,
        (BSTR)L"http://www.google.com",
        NULL, NULL, NULL, NULL
    );
    CHECK_HR(hr, "Navigate");
    printf("Navigation command sent. The browser is now active.\n");

    // The web browser is now running, but we can't see it without a host window.
    // This example is for demonstrating the instantiation, not for a full-fledged
    // UI application.

cleanup:
    // 6. Clean up resources.
    if (pWebBrowser != NULL) {
        printf("Releasing IWebBrowser2 interface.\n");
        // Release the reference to the COM object.
        pWebBrowser->lpVtbl->Release(pWebBrowser);
    }

    // Uninitialize the COM library. This must be the last COM call.
    CoUninitialize();

    printf("Program finished.\n");
    return 0;
}
