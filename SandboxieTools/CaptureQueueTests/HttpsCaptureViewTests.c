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
// SandMan HTTPS capture view model tests
//---------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>

#include "../../SandboxiePlus/SandMan/Views/https_capture_model.h"

static int g_failed;

static int Require(int cond, const char *label)
{
    if (cond)
        return 1;
    fprintf(stderr, "FAIL: %s\n", label);
    g_failed = 1;
    return 0;
}

static const char kSampleEntry[] =
    "{"
    "\"startedDateTime\": \"2026-08-15T12:00:00.000Z\","
    "\"request\": {"
    "\"method\": \"GET\","
    "\"url\": \"https://example.com/secret?x=1\","
    "\"headers\": ["
    "{\"name\": \"Authorization\", \"value\": \"Bearer super-secret\"},"
    "{\"name\": \"Cookie\", \"value\": \"sid=should-not-appear\"}"
    "]"
    "},"
    "\"response\": {\"status\": 204},"
    "\"_sandboxie\": {"
    "\"pid\": 4242,"
    "\"tlsVersion\": \"TLSv1.3\","
    "\"pinningFailed\": false"
    "}"
    "}";


static int TestStartRequiresCapsAndBothPaths(void)
{
    const WCHAR *pcap = L"C:\\tmp\\a.pcapng";
    const WCHAR *har = L"C:\\tmp\\a.har";
    ULONG ready = HTTPS_CAPTURE_CAP_REQUIRED;
    int ok = 1;

    ok &= Require(! HttpsCapture_CanStart(0, pcap, har),
                  "no caps => Start disabled");
    ok &= Require(! HttpsCapture_CanStart(
                      HTTPS_CAPTURE_CAP_INSPECTION, pcap, har),
                  "inspection only => Start disabled");
    ok &= Require(! HttpsCapture_CanStart(ready, NULL, har),
                  "missing PCAPNG path => Start disabled");
    ok &= Require(! HttpsCapture_CanStart(ready, pcap, L""),
                  "empty HAR path => Start disabled");
    ok &= Require(HttpsCapture_CanStart(ready, pcap, har),
                  "caps + both paths => Start enabled");
    return ok;
}


static int TestParseEntryNoSecrets(void)
{
    HTTPS_CAPTURE_ROW row;
    int ok;

    memset(&row, 0, sizeof(row));
    if (! Require(HttpsCapture_ParseEntry(kSampleEntry, &row) == 0,
                  "parse sample HAR entry"))
        return 0;

    ok = Require(strcmp(row.method, "GET") == 0, "method GET") &&
        Require(row.status == 204, "status 204") &&
        Require(strcmp(row.host, "example.com") == 0, "host from URL") &&
        Require(strcmp(row.path, "/secret?x=1") == 0, "path from URL") &&
        Require(row.pid == 4242, "pid from _sandboxie") &&
        Require(strcmp(row.tls, "TLSv1.3") == 0, "tls version") &&
        Require(! row.pinning_failed, "pinning false") &&
        Require(strstr(row.time, "2026-08-15") != NULL, "started time") &&
        Require(strstr(row.host, "secret") == NULL, "host has no secret") &&
        Require(strstr(row.path, "Bearer") == NULL, "path has no auth") &&
        Require(strstr(row.method, "sid=") == NULL, "method has no cookie");
    if (ok) {
        char blob[1024];
        sprintf_s(blob, sizeof(blob), "%s|%s|%s|%s|%s",
                  row.time, row.process, row.method, row.host, row.path);
        ok = Require(strstr(blob, "super-secret") == NULL,
                     "no Authorization plaintext") &&
            Require(strstr(blob, "should-not-appear") == NULL,
                    "no Cookie plaintext");
    }
    return ok;
}


static int TestQueueBoundAndStatus(void)
{
    HTTPS_CAPTURE_ROW rows[2];
    HTTPS_CAPTURE_ROW row;
    ULONG count = 0;
    char status[256];
    int ok;

    memset(&row, 0, sizeof(row));
    strcpy_s(row.method, sizeof(row.method), "GET");
    ok = Require(HttpsCapture_Enqueue(rows, &count, 2, &row) == 1,
                 "enqueue first") &&
        Require(HttpsCapture_Enqueue(rows, &count, 2, &row) == 1,
                "enqueue second") &&
        Require(HttpsCapture_Enqueue(rows, &count, 2, &row) == 0,
                "third is dropped at capacity") &&
        Require(count == 2, "queue stays at capacity");
    if (! ok)
        return 0;
    if (! Require(HttpsCapture_FormatStatus(
                      status, sizeof(status), 12, 3, "C:\\tmp\\a.har") == 0,
                  "format status"))
        return 0;
    return Require(strstr(status, "12") != NULL, "status has exchanges") &&
        Require(strstr(status, "3") != NULL, "status has dropped") &&
        Require(strstr(status, "a.har") != NULL, "status has HAR path") &&
        Require(strstr(status, "PCAPNG") != NULL,
                "status mentions pinning keeps PCAPNG");
}


int main(void)
{
    int ok = TestStartRequiresCapsAndBothPaths() &&
        TestParseEntryNoSecrets() &&
        TestQueueBoundAndStatus();
    if (! ok || g_failed) {
        fprintf(stderr, "https capture view tests failed\n");
        return 1;
    }
    printf("https capture view tests passed\n");
    return 0;
}
