#include <windows.h>
#include <ole2.h>
#include <exdisp.h>  // For IWebBrowser2
#include <stdio.h>

int main(void) {
    HRESULT hr;
    IWebBrowser2 *pWebBrowser = NULL;
    VARIANT empty = {0};

    // Initialize COM library
    hr = CoInitialize(NULL);
    if (FAILED(hr)) {
        printf("Failed to initialize COM: 0x%lx\n", hr);
        return 1;
    }

    // Create an instance of InternetExplorer.Application
    hr = CoCreateInstance(&CLSID_InternetExplorer, NULL, CLSCTX_LOCAL_SERVER,
                          &IID_IWebBrowser2, (void **)&pWebBrowser);
    if (FAILED(hr)) {
        printf("CoCreateInstance failed: 0x%lx\n", hr);
        CoUninitialize();
        return 1;
    }

    // Make browser visible
    pWebBrowser->lpVtbl->put_Visible(pWebBrowser, VARIANT_TRUE);

    // Navigate to the desired URL
    BSTR url = SysAllocString(L"https://github.com/danafaye/WindowsAPIAbuseAtlas");
    hr = pWebBrowser->lpVtbl->Navigate(pWebBrowser, url, &empty, &empty, &empty, &empty);

    if (FAILED(hr)) {
        printf("Navigate failed: 0x%lx\n", hr);
    }

    // Wait for user input before exiting
    printf("Press Enter to exit...\n");
    getchar();

    // Clean up
    SysFreeString(url);
    pWebBrowser->lpVtbl->Release(pWebBrowser);
    CoUninitialize();

    return 0;
}