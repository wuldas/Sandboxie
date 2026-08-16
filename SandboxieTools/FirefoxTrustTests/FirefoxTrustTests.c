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
// Firefox/NSS trust helper tests
//---------------------------------------------------------------------------

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "../SbieCapture/firefox_trust.h"

static int g_failures = 0;


static int Require(int condition, const char *message)
{
    if (! condition) {
        fprintf(stderr, "FAILED: %s\n", message);
        ++g_failures;
    }
    return condition;
}


static void MakeTempDir(WCHAR *buffer, ULONG capacity)
{
    WCHAR tmp[MAX_PATH];
    static ULONG seq = 0;
    GetTempPathW(MAX_PATH, tmp);
    swprintf_s(buffer, capacity, L"%s\\sbie-ff-%lu-%lu",
        tmp, GetCurrentProcessId(), ++seq);
    CreateDirectoryW(buffer, NULL);
}


static int ReadAll(const WCHAR *path, char *buffer, ULONG capacity)
{
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD got = 0;
    if (f == INVALID_HANDLE_VALUE)
        return 0;
    if (! ReadFile(f, buffer, capacity - 1, &got, NULL))
        got = 0;
    buffer[got] = 0;
    CloseHandle(f);
    return 1;
}


static int CountOccurrences(const char *haystack, const char *needle)
{
    int count = 0;
    const char *p = haystack;
    while ((p = strstr(p, needle)) != NULL) {
        ++count;
        p += strlen(needle);
    }
    return count;
}


static int TestEnableEnterpriseRoots(void)
{
    WCHAR dir[MAX_PATH];
    WCHAR userJs[MAX_PATH];
    char content[8192];
    int ok;

    MakeTempDir(dir, MAX_PATH);
    swprintf_s(userJs, MAX_PATH, L"%s\\user.js", dir);

    if (! Require(FirefoxTrust_EnableEnterpriseRoots(dir) ==
            FIREFOX_TRUST_OK, "enable enterprise roots")) {
        RemoveDirectoryW(dir);
        return 0;
    }
    if (! Require(ReadAll(userJs, content, sizeof(content)), "read user.js")) {
        DeleteFileW(userJs);
        RemoveDirectoryW(dir);
        return 0;
    }
    ok = Require(strstr(content, "security.enterprise_roots.enabled") != NULL,
        "user.js contains enterprise_roots pref");

    /* idempotent: a second call must not duplicate the pref */
    if (! Require(FirefoxTrust_EnableEnterpriseRoots(dir) ==
            FIREFOX_TRUST_OK, "enable enterprise roots (idempotent)")) {
        ok = 0;
    }
    if (ReadAll(userJs, content, sizeof(content))) {
        ok = Require(CountOccurrences(content,
                "security.enterprise_roots.enabled") == 1,
            "pref not duplicated") && ok;
    }

    DeleteFileW(userJs);
    RemoveDirectoryW(dir);
    return ok;
}


static int TestBadArgsRejected(void)
{
    return Require(FirefoxTrust_EnableEnterpriseRoots(NULL) ==
            FIREFOX_TRUST_ERROR, "enterprise-roots rejects NULL dir") &&
        Require(FirefoxTrust_ImportCaToNss(NULL, "x", 1, NULL) ==
            FIREFOX_TRUST_ERROR, "import-ca rejects NULL dir") &&
        Require(FirefoxTrust_ImportCaToNss(L"C:\\x", NULL, 0, NULL) ==
            FIREFOX_TRUST_ERROR, "import-ca rejects NULL pem");
}


int main(void)
{
    int ok = 1;
    ok = TestBadArgsRejected() && ok;
    ok = TestEnableEnterpriseRoots() && ok;
    if (! ok)
        return 1;
    printf("firefox trust tests passed\n");
    return 0;
}
