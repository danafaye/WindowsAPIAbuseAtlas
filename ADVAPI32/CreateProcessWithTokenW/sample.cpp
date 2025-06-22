#include <windows.h>
#include <iostream>

int main() {
    // Example: Open the token of a process (e.g., PID 4 - usually SYSTEM)
    DWORD targetPid = 4; // Replace with the PID of a process you can open

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);
    if (!hProcess) {
        std::cerr << "Failed to open target process. Error: " << GetLastError() << std::endl;
        return 1;
    }

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
        std::cerr << "Failed to open process token. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    HANDLE hDuplicateToken = nullptr;
    if (!DuplicateTokenEx(
        hToken,
        TOKEN_ALL_ACCESS,
        nullptr,
        SecurityImpersonation,
        TokenPrimary,
        &hDuplicateToken))
    {
        std::cerr << "Failed to duplicate token. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return 1;
    }

    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = { 0 };

    // Create a new process (cmd.exe) with the duplicated token
    if (!CreateProcessWithTokenW(
        hDuplicateToken,
        LOGON_WITH_PROFILE,
        nullptr,
        L"C:\\Windows\\System32\\cmd.exe",
        CREATE_NEW_CONSOLE,
        nullptr,
        nullptr,
        &si,
        &pi))
    {
        std::cerr << "CreateProcessWithTokenW failed. Error: " << GetLastError() << std::endl;
    }
    else {
        std::cout << "Process launched successfully!" << std::endl;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    CloseHandle(hDuplicateToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return 0;
}