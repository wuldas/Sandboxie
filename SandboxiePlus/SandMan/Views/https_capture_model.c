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
// HTTPS capture view model -- no Qt, no OpenSSL
//---------------------------------------------------------------------------

#include "https_capture_model.h"

#include <stdio.h>
#include <string.h>


static BOOL HttpsCapture_HasPath(const WCHAR *path)
{
    return path && path[0];
}


static const char *HttpsCapture_FindKey(const char *json, const char *key)
{
    char pattern[64];
    const char *hit;

    if (! json || ! key)
        return NULL;
    if (sprintf_s(pattern, sizeof(pattern), "\"%s\"", key) < 0)
        return NULL;
    hit = strstr(json, pattern);
    if (! hit)
        return NULL;
    hit += strlen(pattern);
    while (*hit == ' ' || *hit == '\t' || *hit == '\r' || *hit == '\n' ||
            *hit == ':') {
        ++hit;
    }
    return hit;
}


static int HttpsCapture_CopyJsonString(
    const char *cursor,
    char *dest,
    ULONG destSize)
{
    ULONG index = 0;

    if (! cursor || ! dest || destSize == 0)
        return -1;
    if (*cursor != '"')
        return -1;
    ++cursor;
    while (*cursor && *cursor != '"') {
        char value = *cursor++;
        if (value == '\\' && *cursor) {
            value = *cursor++;
            if (value == 'n')
                value = '\n';
            else if (value == 'r')
                value = '\r';
            else if (value == 't')
                value = '\t';
        }
        if (index + 1 < destSize)
            dest[index++] = value;
    }
    dest[index] = 0;
    return 0;
}


static ULONG HttpsCapture_ParseULong(const char *cursor)
{
    ULONG value = 0;
    if (! cursor)
        return 0;
    while (*cursor >= '0' && *cursor <= '9') {
        value = value * 10ul + (ULONG)(*cursor - '0');
        ++cursor;
    }
    return value;
}


static void HttpsCapture_SplitUrl(
    const char *url,
    char *host,
    ULONG hostSize,
    char *path,
    ULONG pathSize)
{
    const char *scheme;
    const char *slash;

    host[0] = 0;
    path[0] = 0;
    if (! url)
        return;
    scheme = strstr(url, "://");
    if (scheme)
        url = scheme + 3;
    slash = strchr(url, '/');
    if (! slash) {
        strncpy_s(host, hostSize, url, _TRUNCATE);
        strncpy_s(path, pathSize, "/", _TRUNCATE);
        return;
    }
    if ((ULONG)(slash - url) < hostSize) {
        memcpy(host, url, (size_t)(slash - url));
        host[slash - url] = 0;
    }
    else {
        strncpy_s(host, hostSize, url, _TRUNCATE);
    }
    strncpy_s(path, pathSize, slash, _TRUNCATE);
}


BOOL HttpsCapture_CanStart(
    ULONG capabilityFlags,
    const WCHAR *pcapPath,
    const WCHAR *harPath)
{
    if ((capabilityFlags & HTTPS_CAPTURE_CAP_REQUIRED) !=
            HTTPS_CAPTURE_CAP_REQUIRED)
        return FALSE;
    return HttpsCapture_HasPath(pcapPath) && HttpsCapture_HasPath(harPath);
}


int HttpsCapture_ParseEntry(
    const char *json,
    HTTPS_CAPTURE_ROW *row)
{
    const char *cursor;
    char url[512];

    if (! json || ! row)
        return -1;
    memset(row, 0, sizeof(*row));

    cursor = HttpsCapture_FindKey(json, "startedDateTime");
    if (cursor)
        HttpsCapture_CopyJsonString(cursor, row->time, sizeof(row->time));

    cursor = HttpsCapture_FindKey(json, "method");
    if (cursor)
        HttpsCapture_CopyJsonString(cursor, row->method, sizeof(row->method));

    url[0] = 0;
    cursor = HttpsCapture_FindKey(json, "url");
    if (cursor)
        HttpsCapture_CopyJsonString(cursor, url, sizeof(url));
    HttpsCapture_SplitUrl(url, row->host, sizeof(row->host),
                          row->path, sizeof(row->path));

    cursor = HttpsCapture_FindKey(json, "status");
    if (cursor)
        row->status = HttpsCapture_ParseULong(cursor);

    cursor = HttpsCapture_FindKey(json, "pid");
    if (cursor)
        row->pid = HttpsCapture_ParseULong(cursor);

    cursor = HttpsCapture_FindKey(json, "tlsVersion");
    if (cursor)
        HttpsCapture_CopyJsonString(cursor, row->tls, sizeof(row->tls));

    cursor = HttpsCapture_FindKey(json, "pinningFailed");
    if (cursor && strncmp(cursor, "true", 4) == 0)
        row->pinning_failed = TRUE;

    return 0;
}


int HttpsCapture_Enqueue(
    HTTPS_CAPTURE_ROW *rows,
    ULONG *count,
    ULONG capacity,
    const HTTPS_CAPTURE_ROW *row)
{
    if (! rows || ! count || ! row || capacity == 0)
        return 0;
    if (*count >= capacity)
        return 0;
    rows[*count] = *row;
    ++(*count);
    return 1;
}


int HttpsCapture_FormatStatus(
    char *buffer,
    ULONG bufferSize,
    ULONG exchanges,
    ULONG dropped,
    const char *harPath)
{
    if (! buffer || bufferSize == 0)
        return -1;
    if (! harPath)
        harPath = "";
    if (sprintf_s(
            buffer,
            bufferSize,
            "Exchanges: %lu | Dropped: %lu | HAR: %s | pinning failures keep PCAPNG",
            exchanges,
            dropped,
            harPath) < 0) {
        return -1;
    }
    return 0;
}
