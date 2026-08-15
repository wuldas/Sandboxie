/*
 * Copyright 2026 David Xanatos, xanasoft.com
 *
 * Silent boxed process runner for capture live tests.
 * Do not use the installed Start.exe UI path.
 */

#include <windows.h>
#include <stdio.h>
#include <wchar.h>

extern "C" __declspec(dllimport) BOOL SbieDll_RunSandboxed(
    const WCHAR *box_name,
    const WCHAR *cmd,
    const WCHAR *dir,
    ULONG creation_flags,
    STARTUPINFOW *si,
    PROCESS_INFORMATION *pi);

static unsigned long long FileTimeToU64(const FILETIME *value)
{
    ULARGE_INTEGER combined;
    combined.LowPart = value->dwLowDateTime;
    combined.HighPart = value->dwHighDateTime;
    return combined.QuadPart;
}

static int PrintUsage(void)
{
    fwprintf(stderr,
        L"usage: run_boxed_silent.exe <box> <wait|nowait|controlled> "
        L"<command-line> [working-directory]\n");
    return 2;
}

int wmain(int argc, WCHAR **argv)
{
    if (argc < 4 || argc > 5)
        return PrintUsage();

    const WCHAR *box = argv[1];
    const WCHAR *mode = argv[2];
    const WCHAR *command = argv[3];
    WCHAR directory[MAX_PATH];
    if (argc == 5) {
        wcsncpy_s(directory, ARRAYSIZE(directory), argv[4], _TRUNCATE);
    }
    else if (!GetCurrentDirectoryW(ARRAYSIZE(directory), directory)) {
        fwprintf(stderr, L"GetCurrentDirectory failed: %lu\n", GetLastError());
        return 3;
    }

    BOOL wait = _wcsicmp(mode, L"wait") == 0;
    BOOL controlled = _wcsicmp(mode, L"controlled") == 0;
    if (!wait && !controlled && _wcsicmp(mode, L"nowait") != 0)
        return PrintUsage();

    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    ZeroMemory(&startup, sizeof(startup));
    ZeroMemory(&process, sizeof(process));
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;

    ULONG creationFlags = CREATE_NO_WINDOW;
    if (controlled)
        creationFlags |= CREATE_SUSPENDED;

    if (!SbieDll_RunSandboxed(
            box, command, directory, creationFlags, &startup, &process)) {
        DWORD error = GetLastError();
        fwprintf(stderr, L"SbieDll_RunSandboxed failed: %lu (0x%08lX)\n",
                 error, error);
        return 4;
    }

    FILETIME creationTime, exitTime, kernelTime, userTime;
    ZeroMemory(&creationTime, sizeof(creationTime));
    if (!GetProcessTimes(
            process.hProcess, &creationTime, &exitTime, &kernelTime, &userTime)) {
        DWORD error = GetLastError();
        TerminateProcess(process.hProcess, error);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        fwprintf(stderr, L"GetProcessTimes failed: %lu\n", error);
        return 5;
    }

    wprintf(L"{\"pid\":%lu,\"tid\":%lu,\"createTime\":\"%llu\","
            L"\"controlled\":%s}\n",
            process.dwProcessId,
            process.dwThreadId,
            FileTimeToU64(&creationTime),
            controlled ? L"true" : L"false");
    fflush(stdout);

    if (controlled) {
        WCHAR signal[8];
        if (!fgetws(signal, ARRAYSIZE(signal), stdin)) {
            TerminateProcess(process.hProcess, ERROR_CANCELLED);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
            fwprintf(stderr, L"resume signal missing\n");
            return 6;
        }
        if (ResumeThread(process.hThread) == (DWORD)-1) {
            DWORD error = GetLastError();
            TerminateProcess(process.hProcess, error);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
            fwprintf(stderr, L"ResumeThread failed: %lu\n", error);
            return 7;
        }
        wait = TRUE;
    }

    DWORD exitCode = STILL_ACTIVE;
    if (wait) {
        DWORD waitStatus = WaitForSingleObject(process.hProcess, INFINITE);
        if (waitStatus != WAIT_OBJECT_0 ||
                !GetExitCodeProcess(process.hProcess, &exitCode)) {
            DWORD error = GetLastError();
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
            fwprintf(stderr, L"wait failed: %lu\n", error);
            return 8;
        }
        wprintf(L"{\"pid\":%lu,\"exitCode\":%lu}\n",
                process.dwProcessId, exitCode);
        fflush(stdout);
    }

    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return wait ? (int)exitCode : 0;
}
