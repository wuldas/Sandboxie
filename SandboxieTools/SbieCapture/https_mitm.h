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
#include "../../Sandboxie/core/drv/capture_https.h"

#define HTTPS_MITM_OK               0
#define HTTPS_MITM_ERROR            (-1)
#define HTTPS_MITM_REJECTED         (-2)

typedef struct _HTTPS_MITM_OPTIONS {

    CAPTURE_CA *ca;
    const HTTPS_REDIRECT_CONTEXT *expected_context;
    const char *upstream_host;
    USHORT upstream_port;
    const char *upstream_ca_pem;
    const WCHAR *har_path;
    HANDLE har_file;
    HANDLE keylog_file;
    BOOL redact;
    BOOL include_bodies;
    BOOL allow_unverified_upstream;

} HTTPS_MITM_OPTIONS;

typedef struct _HTTPS_MITM HTTPS_MITM;

#ifdef __cplusplus
extern "C" {
#endif

HTTPS_MITM *HttpsMitm_Listen(const HTTPS_MITM_OPTIONS *options);
USHORT HttpsMitm_ListenPort(const HTTPS_MITM *mitm);
SOCKET HttpsMitm_Accept(HTTPS_MITM *mitm);
SOCKET HttpsMitm_TryAccept(HTTPS_MITM *mitm, ULONG timeoutMs);
int HttpsMitm_RecvContext(SOCKET client, HTTPS_REDIRECT_CONTEXT *context);
int HttpsMitm_QueryRedirectContext(
    SOCKET client,
    HTTPS_REDIRECT_CONTEXT *context);
int HttpsMitm_QueryRedirectContextEx(
    SOCKET client,
    HTTPS_REDIRECT_CONTEXT *context,
    ULONG *wsaError);
int HttpsMitm_ServeOnce(
    HTTPS_MITM *mitm,
    SOCKET client,
    const HTTPS_REDIRECT_CONTEXT *context);
void HttpsMitm_Close(HTTPS_MITM *mitm);

#ifdef __cplusplus
}
#endif

#endif /* _MY_HTTPS_MITM_H */
