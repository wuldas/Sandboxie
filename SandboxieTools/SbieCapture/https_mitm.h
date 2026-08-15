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
// HTTPS MITM listener -- public API, no OpenSSL types
//---------------------------------------------------------------------------

#ifndef _MY_HTTPS_MITM_H
#define _MY_HTTPS_MITM_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "capture_ca.h"

#define HTTPS_MITM_OK               0
#define HTTPS_MITM_ERROR            (-1)
#define HTTPS_MITM_REJECTED         (-2)

#define HTTPS_REDIRECT_CONTEXT_MAGIC    0x48524443ul
#define HTTPS_REDIRECT_CONTEXT_VERSION  1

typedef struct _HTTPS_REDIRECT_CONTEXT {

    ULONG magic;
    ULONG version;
    ULONG64 capture_id_high;
    ULONG64 capture_id_low;
    ULONG64 generation;
    ULONG process_id;
    ULONG session_id;
    ULONG64 process_create_time;
    ULONG address_family;
    USHORT original_port;
    USHORT reserved;
    UCHAR original_address[16];

} HTTPS_REDIRECT_CONTEXT;

typedef struct _HTTPS_MITM_OPTIONS {

    CAPTURE_CA *ca;
    const HTTPS_REDIRECT_CONTEXT *expected_context;
    const char *upstream_host;
    USHORT upstream_port;
    const char *upstream_ca_pem;
    const WCHAR *har_path;
    BOOL redact;
    BOOL include_bodies;

} HTTPS_MITM_OPTIONS;

typedef struct _HTTPS_MITM HTTPS_MITM;

#ifdef __cplusplus
extern "C" {
#endif

HTTPS_MITM *HttpsMitm_Listen(const HTTPS_MITM_OPTIONS *options);
USHORT HttpsMitm_ListenPort(const HTTPS_MITM *mitm);
SOCKET HttpsMitm_Accept(HTTPS_MITM *mitm);
int HttpsMitm_ServeOnce(
    HTTPS_MITM *mitm,
    SOCKET client,
    const HTTPS_REDIRECT_CONTEXT *context);
void HttpsMitm_Close(HTTPS_MITM *mitm);

#ifdef __cplusplus
}
#endif

#endif /* _MY_HTTPS_MITM_H */
