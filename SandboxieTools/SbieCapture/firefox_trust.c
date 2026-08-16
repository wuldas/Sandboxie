/*
 * Copyright 2026 David Xanatos, xanasoft.com
 *
 * This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//---------------------------------------------------------------------------
// Firefox/NSS trust helpers (boxed-profile-only, opt-in)
//---------------------------------------------------------------------------

#include "firefox_trust.h"

#include <stdio.h>
#include <string.h>

int FirefoxTrust_EnableEnterpriseRoots(const WCHAR *profileDir)
{
    WCHAR userJs[2 * MAX_PATH];
    HANDLE file;
    char content[8192];
    DWORD readSize = 0;
    static const char kPref[] =
        "user_pref(\"security.enterprise_roots.enabled\", true);\r\n";

    if (! profileDir || ! profileDir[0])
        return FIREFOX_TRUST_ERROR;
    if (swprintf_s(userJs, ARRAYSIZE(userJs),
            L"%s\\user.js", profileDir) < 0) {
        return FIREFOX_TRUST_ERROR;
    }

    file = CreateFileW(userJs, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return FIREFOX_TRUST_ERROR;

    /* read the existing user.js (if any) to detect an already-present pref */
    if (! ReadFile(file, content, sizeof(content) - 1, &readSize, NULL))
        readSize = 0;
    content[readSize] = 0;
    if (strstr(content, "security.enterprise_roots.enabled") != NULL) {
        CloseHandle(file);
        return FIREFOX_TRUST_OK;    /* already enabled -- idempotent */
    }

    /* append the pref at the end of user.js */
    {
        DWORD written;
        if (SetFilePointer(file, 0, NULL, FILE_END) ==
                INVALID_SET_FILE_POINTER ||
                ! WriteFile(file, kPref, (DWORD)strlen(kPref),
                    &written, NULL)) {
            CloseHandle(file);
            return FIREFOX_TRUST_ERROR;
        }
    }
    CloseHandle(file);
    return FIREFOX_TRUST_OK;
}


int FirefoxTrust_ImportCaToNss(
    const WCHAR *profileDir,
    const char *caPem,
    ULONG pemLength,
    const WCHAR *certutilPath)
{
    WCHAR tmpPath[MAX_PATH];
    WCHAR dbSpec[1024];
    WCHAR cmdLine[2048];
    HANDLE tmp;
    DWORD written;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD exitCode = 1;
    int ok = FIREFOX_TRUST_ERROR;

    if (! profileDir || ! profileDir[0] || ! caPem || ! pemLength)
        return FIREFOX_TRUST_ERROR;

    /* stage the CA PEM to a temp file for `certutil -i` */
    if (GetTempPathW(ARRAYSIZE(tmpPath), tmpPath) == 0)
        return FIREFOX_TRUST_ERROR;
    if (swprintf_s(tmpPath, ARRAYSIZE(tmpPath),
            L"%s\\sbiecapture-ca.pem", tmpPath) < 0) {
        return FIREFOX_TRUST_ERROR;
    }
    tmp = CreateFileW(tmpPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (tmp == INVALID_HANDLE_VALUE)
        return FIREFOX_TRUST_ERROR;
    if (! WriteFile(tmp, caPem, pemLength, &written, NULL) ||
            written != pemLength) {
        CloseHandle(tmp);
        DeleteFileW(tmpPath);
        return FIREFOX_TRUST_ERROR;
    }
    CloseHandle(tmp);

    if (swprintf_s(dbSpec, ARRAYSIZE(dbSpec), L"sql:%s", profileDir) < 0)
        goto done;
    if (swprintf_s(cmdLine, ARRAYSIZE(cmdLine),
            L"\"%s\" -A -n \"SbieCapture Session CA\" -t \"C,,\" "
            L"-i \"%s\" -d \"%s\"",
            certutilPath && certutilPath[0] ? certutilPath : L"certutil",
            tmpPath, dbSpec) < 0) {
        goto done;
    }

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    if (! CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        goto done;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    if (! GetExitCodeProcess(pi.hProcess, &exitCode))
        exitCode = 1;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    ok = exitCode == 0 ? FIREFOX_TRUST_OK : FIREFOX_TRUST_ERROR;

done:
    DeleteFileW(tmpPath);
    return ok;
}
