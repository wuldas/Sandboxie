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
// Capture Server -- wire protocol
//---------------------------------------------------------------------------

#ifndef _MY_CAPTUREWIRE_H
#define _MY_CAPTUREWIRE_H


#include "../../common/defines.h"
#include "msgids.h"


//---------------------------------------------------------------------------
// Defines
//---------------------------------------------------------------------------


#define CAPTURE_WIRE_VERSION                    1

#define CAPTURE_MAX_REQUEST_SIZE                4096
#define CAPTURE_MAX_EVENT_ENTRIES               32
#define CAPTURE_MAX_REPLY_SIZE                  (64 * 1024)

#define CAPTURE_CAP_CONTROL                     0x00000001
#define CAPTURE_CAP_CONNECTION_AUDIT            0x00000002
#define CAPTURE_CAP_PACKET_CAPTURE              0x00000004
#define CAPTURE_CAP_HTTPS_INSPECTION            0x00000008
#define CAPTURE_CAP_PCAPNG_EXPORT               0x00000010
#define CAPTURE_CAP_HAR_EXPORT                  0x00000020

#define CAPTURE_SCOPE_BOX                       1
#define CAPTURE_SCOPE_PROCESS                   2

#define CAPTURE_MODE_CONNECTIONS                0x00000001
#define CAPTURE_MODE_PACKETS                    0x00000002
#define CAPTURE_MODE_HTTPS                      0x00000004

#define CAPTURE_FLAG_INCLUDE_FUTURE_PROCESSES   0x00000001
#define CAPTURE_FLAG_INCLUDE_LOOPBACK           0x00000002

#define CAPTURE_ADDRESS_FAMILY_IPV4             2
#define CAPTURE_ADDRESS_FAMILY_IPV6             23

#define CAPTURE_STATE_STARTING                  1
#define CAPTURE_STATE_WAITING_FOR_BACKEND       2
#define CAPTURE_STATE_RUNNING                   3
#define CAPTURE_STATE_STOPPED                   4
#define CAPTURE_STATE_FAILED                    5


#pragma pack(push, 8)


//---------------------------------------------------------------------------
// Common Structures
//---------------------------------------------------------------------------


typedef struct _CAPTURE_VERSIONED_REQUEST {

    MSG_HEADER h;
    ULONG wire_version;
    ULONG struct_size;

} CAPTURE_VERSIONED_REQUEST;


typedef struct _CAPTURE_SESSION_ID {

    ULONG64 high;
    ULONG64 low;

} CAPTURE_SESSION_ID;


typedef struct _CAPTURE_SESSION_INFO {

    CAPTURE_SESSION_ID capture_id;
    ULONG state;
    ULONG scope;
    ULONG mode;
    ULONG flags;
    ULONG target_pid;
    ULONG target_session_id;
    ULONG64 target_process_create_time;
    ULONG64 started_time;
    ULONG64 stopped_time;
    ULONG64 event_count;
    ULONG64 packet_count;
    ULONG64 byte_count;
    ULONG64 dropped_count;
    ULONG backend_status;
    ULONG reserved;
    WCHAR box_name[BOXNAME_COUNT];

} CAPTURE_SESSION_INFO;


//---------------------------------------------------------------------------
// Query Capabilities
//---------------------------------------------------------------------------


typedef struct _CAPTURE_QUERY_CAPS_REQ {

    CAPTURE_VERSIONED_REQUEST v;

} CAPTURE_QUERY_CAPS_REQ;


typedef struct _CAPTURE_QUERY_CAPS_RPL {

    MSG_HEADER h;
    ULONG wire_version;
    ULONG struct_size;
    ULONG min_wire_version;
    ULONG max_wire_version;
    ULONG capabilities;
    ULONG max_sessions_per_owner;
    ULONG max_list_entries;
    ULONG max_event_entries;

} CAPTURE_QUERY_CAPS_RPL;


//---------------------------------------------------------------------------
// Start Capture
//---------------------------------------------------------------------------


typedef struct _CAPTURE_START_REQ {

    CAPTURE_VERSIONED_REQUEST v;
    ULONG scope;
    ULONG mode;
    ULONG flags;
    ULONG target_pid;
    WCHAR box_name[BOXNAME_COUNT];

} CAPTURE_START_REQ;


typedef struct _CAPTURE_START_RPL {

    MSG_HEADER h;
    ULONG wire_version;
    ULONG struct_size;
    CAPTURE_SESSION_INFO session;

} CAPTURE_START_RPL;


//---------------------------------------------------------------------------
// Stop and Query Capture
//---------------------------------------------------------------------------


typedef struct _CAPTURE_SESSION_REQ {

    CAPTURE_VERSIONED_REQUEST v;
    CAPTURE_SESSION_ID capture_id;

} CAPTURE_SESSION_REQ;


typedef struct _CAPTURE_STATUS_RPL {

    MSG_HEADER h;
    ULONG wire_version;
    ULONG struct_size;
    CAPTURE_SESSION_INFO session;

} CAPTURE_STATUS_RPL;


//---------------------------------------------------------------------------
// List Captures
//---------------------------------------------------------------------------


typedef struct _CAPTURE_LIST_REQ {

    CAPTURE_VERSIONED_REQUEST v;
    ULONG start_index;
    ULONG max_entries;

} CAPTURE_LIST_REQ;


typedef struct _CAPTURE_LIST_RPL {

    MSG_HEADER h;
    ULONG wire_version;
    ULONG struct_size;
    ULONG total_count;
    ULONG returned_count;
    ULONG next_index;
    ULONG reserved;
    CAPTURE_SESSION_INFO sessions[1];

} CAPTURE_LIST_RPL;


//---------------------------------------------------------------------------
// Read Connection-Audit Events (destructive bounded drain)
//---------------------------------------------------------------------------


typedef struct _CAPTURE_CONNECTION_EVENT {

    ULONG64 sequence;
    ULONG64 timestamp;
    ULONG64 process_create_time;
    ULONG process_id;
    ULONG session_id;
    USHORT address_family;
    UCHAR protocol;
    UCHAR event_type;
    UCHAR direction;
    UCHAR blocked;
    UCHAR loopback;
    UCHAR reserved1;
    USHORT local_port;
    USHORT remote_port;
    ULONG reserved2;
    UCHAR local_address[16];
    UCHAR remote_address[16];

} CAPTURE_CONNECTION_EVENT;


typedef struct _CAPTURE_READ_EVENTS_REQ {

    CAPTURE_VERSIONED_REQUEST v;
    CAPTURE_SESSION_ID capture_id;
    ULONG max_events;
    ULONG reserved;

} CAPTURE_READ_EVENTS_REQ;


typedef struct _CAPTURE_READ_EVENTS_RPL {

    MSG_HEADER h;
    ULONG wire_version;
    ULONG struct_size;
    CAPTURE_SESSION_ID capture_id;
    ULONG64 next_sequence;
    ULONG64 oldest_sequence;
    ULONG64 newest_sequence;
    ULONG64 dropped_count;
    ULONG returned_events;
    ULONG remaining_events;
    ULONG reserved1;
    ULONG reserved2;
    CAPTURE_CONNECTION_EVENT events[1];

} CAPTURE_READ_EVENTS_RPL;


#pragma pack(pop)


#ifdef __cplusplus
static_assert(sizeof(CAPTURE_VERSIONED_REQUEST) == 16,
              "capture wire request header size changed");
static_assert(sizeof(CAPTURE_SESSION_ID) == 16,
              "capture session id size changed");
static_assert(sizeof(CAPTURE_SESSION_INFO) == 184,
              "capture session info size changed");
static_assert(sizeof(CAPTURE_QUERY_CAPS_RPL) == 40,
              "capture capabilities reply size changed");
static_assert(sizeof(CAPTURE_START_REQ) == 112,
              "capture start request size changed");
static_assert(sizeof(CAPTURE_START_RPL) == 200,
              "capture start reply size changed");
static_assert(sizeof(CAPTURE_SESSION_REQ) == 32,
              "capture session request size changed");
static_assert(sizeof(CAPTURE_STATUS_RPL) == 200,
              "capture status reply size changed");
static_assert(sizeof(CAPTURE_LIST_REQ) == 24,
              "capture list request size changed");
static_assert(FIELD_OFFSET(CAPTURE_LIST_RPL, sessions) == 32,
              "capture list header size changed");
static_assert(sizeof(CAPTURE_CONNECTION_EVENT) == 80,
              "capture connection event size changed");
static_assert(sizeof(CAPTURE_READ_EVENTS_REQ) == 40,
              "capture event request size changed");
static_assert(FIELD_OFFSET(CAPTURE_READ_EVENTS_RPL, events) == 80,
              "capture event reply header size changed");
#endif


//---------------------------------------------------------------------------


#endif /* _MY_CAPTUREWIRE_H */
