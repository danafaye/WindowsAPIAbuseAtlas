#include <windows.h>

int main() {
    const char* url = "https://github.com/danafaye/WindowsAPIAbuseAtlas";

    ShellExecuteA(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);

    return 0;
}
