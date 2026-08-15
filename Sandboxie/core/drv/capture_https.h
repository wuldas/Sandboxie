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
// HTTPS connect-redirect decision + shared WFP context
//---------------------------------------------------------------------------

#ifndef _MY_CAPTURE_HTTPS_H
#define _MY_CAPTURE_HTTPS_H


#if defined(KERNEL_MODE) || defined(_NTDDK_) || defined(_NTIFS_) || \
        defined(_WDMDDK_)
#include <ntddk.h>
#else
#include <windows.h>
#endif

#include "capture_filter.h"


#define HTTPS_REDIRECT_CONTEXT_MAGIC    0x48524443ul
#define HTTPS_REDIRECT_CONTEXT_VERSION  1

#define CAPTURE_HTTPS_DECISION_CONTINUE 0
#define CAPTURE_HTTPS_DECISION_REDIRECT 1

#define CAPTURE_HTTPS_TCP               6
#define CAPTURE_HTTPS_PORT              443
#define CAPTURE_HTTPS_AF_INET           2
#define CAPTURE_HTTPS_AF_INET6          23


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


typedef struct _CAPTURE_HTTPS_FLOW {

    const CAPTURE_FILTER_TARGET *target;
    const CAPTURE_FILTER_IDENTITY *identity;
    ULONG protocol;
    ULONG address_family;
    USHORT remote_port;
    USHORT listen_port;
    BOOLEAN already_redirected_by_self;
    UCHAR remote_address[16];

} CAPTURE_HTTPS_FLOW;


#ifdef __cplusplus
extern "C" {
#endif

BOOLEAN CaptureHttps_IsListenerDestination(
    ULONG addressFamily,
    const UCHAR remoteAddress[16],
    USHORT remotePort,
    USHORT listenPort);

ULONG CaptureHttps_Decide(const CAPTURE_HTTPS_FLOW *flow);

void CaptureHttps_FillContext(
    HTTPS_REDIRECT_CONTEXT *context,
    ULONG64 captureIdHigh,
    ULONG64 captureIdLow,
    ULONG64 generation,
    const CAPTURE_FILTER_IDENTITY *identity,
    ULONG addressFamily,
    USHORT originalPort,
    const UCHAR originalAddress[16]);

#ifdef __cplusplus
}
#endif


#endif /* _MY_CAPTURE_HTTPS_H */
