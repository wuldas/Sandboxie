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
// HTTPS connect-redirect decision
//---------------------------------------------------------------------------

#include "capture_https.h"

#ifndef KERNEL_MODE
#include <string.h>
#endif


static BOOLEAN CaptureHttps_IsIpv4Loopback(const UCHAR address[16])
{
    return address[0] == 127 &&
        address[1] == 0 &&
        address[2] == 0 &&
        address[3] == 1 &&
        address[4] == 0 && address[5] == 0 && address[6] == 0 &&
        address[7] == 0 && address[8] == 0 && address[9] == 0 &&
        address[10] == 0 && address[11] == 0 && address[12] == 0 &&
        address[13] == 0 && address[14] == 0 && address[15] == 0;
}


static BOOLEAN CaptureHttps_IsIpv6Loopback(const UCHAR address[16])
{
    ULONG index;
    for (index = 0; index < 15; ++index) {
        if (address[index] != 0)
            return FALSE;
    }
    return address[15] == 1;
}


BOOLEAN CaptureHttps_IsListenerDestination(
    ULONG addressFamily,
    const UCHAR remoteAddress[16],
    USHORT remotePort,
    USHORT listenPort)
{
    if (! remoteAddress || listenPort == 0 || remotePort != listenPort)
        return FALSE;
    if (addressFamily == CAPTURE_HTTPS_AF_INET)
        return CaptureHttps_IsIpv4Loopback(remoteAddress);
    if (addressFamily == CAPTURE_HTTPS_AF_INET6)
        return CaptureHttps_IsIpv6Loopback(remoteAddress);
    return FALSE;
}


ULONG CaptureHttps_Decide(const CAPTURE_HTTPS_FLOW *flow)
{
    if (! flow || ! flow->identity)
        return CAPTURE_HTTPS_DECISION_CONTINUE;
    if (flow->already_redirected_by_self)
        return CAPTURE_HTTPS_DECISION_CONTINUE;
    if (flow->listen_port == 0)
        return CAPTURE_HTTPS_DECISION_CONTINUE;
    if (flow->protocol != CAPTURE_HTTPS_TCP ||
            flow->remote_port != CAPTURE_HTTPS_PORT) {
        return CAPTURE_HTTPS_DECISION_CONTINUE;
    }
    if (CaptureHttps_IsListenerDestination(
            flow->address_family,
            flow->remote_address,
            flow->remote_port,
            flow->listen_port)) {
        return CAPTURE_HTTPS_DECISION_CONTINUE;
    }
    if (flow->target &&
            ! CaptureFilter_Matches(flow->target, flow->identity))
        return CAPTURE_HTTPS_DECISION_CONTINUE;
    if (! flow->identity)
        return CAPTURE_HTTPS_DECISION_CONTINUE;
    return CAPTURE_HTTPS_DECISION_REDIRECT;
}


void CaptureHttps_FillContext(
    HTTPS_REDIRECT_CONTEXT *context,
    ULONG64 captureIdHigh,
    ULONG64 captureIdLow,
    ULONG64 generation,
    const CAPTURE_FILTER_IDENTITY *identity,
    ULONG addressFamily,
    USHORT originalPort,
    const UCHAR originalAddress[16])
{
    ULONG index;

    if (! context)
        return;
#ifdef KERNEL_MODE
    RtlZeroMemory(context, sizeof(*context));
#else
    memset(context, 0, sizeof(*context));
#endif
    if (! identity || ! originalAddress)
        return;

    context->magic = HTTPS_REDIRECT_CONTEXT_MAGIC;
    context->version = HTTPS_REDIRECT_CONTEXT_VERSION;
    context->capture_id_high = captureIdHigh;
    context->capture_id_low = captureIdLow;
    context->generation = generation;
    context->process_id = identity->process_id;
    context->session_id = identity->session_id;
    context->process_create_time = identity->process_create_time;
    context->address_family = addressFamily;
    context->original_port = originalPort;
    context->reserved = 0;
    for (index = 0; index < 16; ++index)
        context->original_address[index] = originalAddress[index];
}
