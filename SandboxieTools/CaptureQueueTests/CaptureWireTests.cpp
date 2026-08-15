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
// Capture Wire Boundary Tests
//---------------------------------------------------------------------------

#include <ntstatus.h>
#define WIN32_NO_STATUS
typedef long NTSTATUS;

#include <windows.h>
#include <stddef.h>
#include <stdio.h>

#include "../../Sandboxie/common/win32_ntddk.h"
#include "../../Sandboxie/common/defines.h"

#undef C_ASSERT
#define C_ASSERT(expression) static_assert((expression), #expression)

#include "../../Sandboxie/core/drv/api_defs.h"
#include "../../Sandboxie/core/svc/capturewire.h"


static_assert(sizeof(CAPTURE_DRIVER_EVENT) ==
              sizeof(CAPTURE_CONNECTION_EVENT),
              "driver and service event sizes differ");
static_assert(offsetof(CAPTURE_DRIVER_EVENT, sequence) ==
              offsetof(CAPTURE_CONNECTION_EVENT, sequence),
              "driver and service sequence offsets differ");
static_assert(offsetof(CAPTURE_DRIVER_EVENT, local_address) ==
              offsetof(CAPTURE_CONNECTION_EVENT, local_address),
              "driver and service local-address offsets differ");
static_assert(offsetof(CAPTURE_DRIVER_EVENT, remote_address) ==
              offsetof(CAPTURE_CONNECTION_EVENT, remote_address),
              "driver and service remote-address offsets differ");
static_assert(CAPTURE_DRIVER_EVENT_CONNECT == 1,
              "driver connect event value changed");
static_assert(CAPTURE_DRIVER_EVENT_ACCEPT == 2,
              "driver accept event value changed");
static_assert(CAPTURE_DRIVER_DIRECTION_OUTBOUND == 1,
              "driver outbound value changed");
static_assert(CAPTURE_DRIVER_DIRECTION_INBOUND == 2,
              "driver inbound value changed");


static int Require(bool condition, const char *message)
{
    if (! condition) {
        fprintf(stderr, "FAILED: %s\n", message);
        return 0;
    }
    return 1;
}


int main()
{
    const size_t maximumEventReply =
        offsetof(CAPTURE_READ_EVENTS_RPL, events) +
        CAPTURE_MAX_EVENT_ENTRIES * sizeof(CAPTURE_CONNECTION_EVENT);
    const size_t maximumListReply =
        offsetof(CAPTURE_LIST_RPL, sessions) +
        64 * sizeof(CAPTURE_SESSION_INFO);
    const size_t maximumPacketReply =
        offsetof(CAPTURE_READ_PACKETS_RPL, records) +
        CAPTURE_MAX_PACKET_ENTRIES * sizeof(CAPTURE_PACKET_EVENT);
    const size_t maximumStreamReply =
        offsetof(CAPTURE_READ_STREAMS_RPL, records) +
        CAPTURE_MAX_STREAM_ENTRIES * sizeof(CAPTURE_STREAM_EVENT);

    if (!Require(sizeof(CAPTURE_READ_EVENTS_REQ) <= CAPTURE_MAX_REQUEST_SIZE,
                 "event request exceeds service request limit") ||
            !Require(maximumEventReply <= CAPTURE_MAX_REPLY_SIZE,
                     "event reply exceeds Capture reply limit") ||
            !Require(maximumListReply <= CAPTURE_MAX_REPLY_SIZE,
                     "list reply exceeds Capture reply limit") ||
            !Require(maximumPacketReply <= CAPTURE_MAX_REPLY_SIZE,
                     "packet reply exceeds Capture reply limit") ||
            !Require(maximumStreamReply <= CAPTURE_MAX_REPLY_SIZE,
                     "stream reply exceeds Capture reply limit") ||
            !Require(sizeof(CAPTURE_PACKET_EVENT) == 1600,
                     "packet event size changed") ||
            !Require(sizeof(CAPTURE_STREAM_EVENT) == 1600,
                     "stream event size changed") ||
            !Require(MSGID_CAPTURE_READ_PACKETS == 0x2008,
                     "packet read msgid is not 0x2008") ||
            !Require(MSGID_CAPTURE_READ_STREAMS == 0x2009,
                     "stream read msgid is not 0x2009") ||
            !Require(CAPTURE_DRIVER_MAX_READ_EVENTS ==
                     CAPTURE_MAX_EVENT_ENTRIES,
                     "driver and service event batch limits differ") ||
            !Require(MSGID_CAPTURE_SET_EXPORT == 0x2007,
                     "export msgid is not 0x2007") ||
            !Require(CAPTURE_START_REQ_V1_SIZE == 112,
                     "v1 start size changed") ||
            !Require(FIELD_OFFSET(CAPTURE_START_REQ, snap_length) ==
                     CAPTURE_START_REQ_V1_SIZE,
                     "start trailing fields moved") ||
            !Require(sizeof(CAPTURE_START_REQ) == 132,
                     "extended start request size changed") ||
            !Require(sizeof(CAPTURE_SET_EXPORT_REQ) == 48,
                     "export request size changed") ||
            !Require(sizeof(CAPTURE_SET_EXPORT_REQ) <=
                     CAPTURE_MAX_REQUEST_SIZE,
                     "export request exceeds service request limit") ||
            !Require(sizeof(CAPTURE_SET_EXPORT_RPL) ==
                     sizeof(CAPTURE_STATUS_RPL),
                     "export reply size diverged from status")) {
        return 1;
    }

    printf("capture wire tests passed\n");
    return 0;
}
