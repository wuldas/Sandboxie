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
// HTTP/1.1 request/response framing
//---------------------------------------------------------------------------

#ifndef _MY_HTTP11_H
#define _MY_HTTP11_H

#include <windows.h>

#define HTTP11_OK                   0
#define HTTP11_NEED_MORE            1
#define HTTP11_ERROR                (-1)

#define HTTP11_MAX_LINE             8192
#define HTTP11_MAX_HEADERS          64
#define HTTP11_MAX_NAME             64
#define HTTP11_MAX_VALUE            2048
#define HTTP11_MAX_METHOD           16
#define HTTP11_MAX_TARGET           2048
#define HTTP11_MAX_REASON           64
#define HTTP11_MAX_VERSION          16

typedef struct _HTTP11_HEADER {

    char name[HTTP11_MAX_NAME];
    char value[HTTP11_MAX_VALUE];

} HTTP11_HEADER;

typedef struct _HTTP11_REQUEST {

    char method[HTTP11_MAX_METHOD];
    char target[HTTP11_MAX_TARGET];
    char version[HTTP11_MAX_VERSION];
    ULONG header_count;
    HTTP11_HEADER headers[HTTP11_MAX_HEADERS];
    ULONG header_bytes;
    ULONG content_length;
    BOOL chunked;

} HTTP11_REQUEST;

typedef struct _HTTP11_RESPONSE {

    char version[HTTP11_MAX_VERSION];
    ULONG status;
    char reason[HTTP11_MAX_REASON];
    ULONG header_count;
    HTTP11_HEADER headers[HTTP11_MAX_HEADERS];
    ULONG header_bytes;
    ULONG content_length;
    BOOL chunked;

} HTTP11_RESPONSE;

#ifdef __cplusplus
extern "C" {
#endif

int Http11_ParseRequest(
    const UCHAR *data,
    ULONG size,
    HTTP11_REQUEST *out);

int Http11_ParseResponse(
    const UCHAR *data,
    ULONG size,
    HTTP11_RESPONSE *out);

const HTTP11_HEADER *Http11_FindHeader(
    const HTTP11_HEADER *headers,
    ULONG count,
    const char *name);

#ifdef __cplusplus
}
#endif

#endif /* _MY_HTTP11_H */
