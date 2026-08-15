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
// HAR 1.2 writer -- HTTP/1.1 exchanges only
//---------------------------------------------------------------------------

#ifndef _MY_HAR_H
#define _MY_HAR_H

#include "http11.h"

#define HAR_OK                      0
#define HAR_ERROR                   (-1)

typedef struct _HAR_EXCHANGE {

    ULONG64 started_filetime;
    ULONG elapsed_ms;
    const HTTP11_REQUEST *request;
    const HTTP11_RESPONSE *response;
    const char *sni_host;
    const char *server_ip;
    ULONG process_id;
    ULONG session_id;
    ULONG64 process_create_time;
    const WCHAR *box_name;
    const WCHAR *sid_string;
    const char *tls_version;
    const char *alpn;
    BOOL pinning_failed;
    BOOL include_bodies;
    BOOL redact;
    const UCHAR *request_body;
    ULONG request_body_len;
    ULONG request_body_original_len;
    const UCHAR *response_body;
    ULONG response_body_len;
    ULONG response_body_original_len;
    ULONG body_cap;

} HAR_EXCHANGE;

typedef struct _HAR_WRITER HAR_WRITER;

#ifdef __cplusplus
extern "C" {
#endif

HAR_WRITER *HarWriter_OpenPath(const WCHAR *path);
HAR_WRITER *HarWriter_OpenHandle(HANDLE file);
int HarWriter_WriteExchange(HAR_WRITER *writer, const HAR_EXCHANGE *exchange);
void HarWriter_Close(HAR_WRITER *writer);

#ifdef __cplusplus
}
#endif

#endif /* _MY_HAR_H */
