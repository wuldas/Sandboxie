/*
 * Copyright 2026 David Xanatos, xanasoft.com
 *
 * This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

//---------------------------------------------------------------------------
// Capture broker shared section wire
//---------------------------------------------------------------------------

#ifndef _MY_CAPTUREBROKERWIRE_H
#define _MY_CAPTUREBROKERWIRE_H


#include "../../common/defines.h"
#include "../drv/capture_packet.h"


#define CAPTURE_BROKER_SECTION_MAGIC       0x53424350u
#define CAPTURE_BROKER_SECTION_VERSION     1
#define CAPTURE_BROKER_MAX_RECORD_CAPACITY 4096

#define CAPTURE_BROKER_STATE_STARTING      1
#define CAPTURE_BROKER_STATE_RUNNING       2
#define CAPTURE_BROKER_STATE_STOPPED       3
#define CAPTURE_BROKER_STATE_FAILED        4


#pragma pack(push, 8)


typedef struct _CAPTURE_BROKER_SECTION {

    ULONG magic;
    ULONG version;
    ULONG size;
    ULONG record_capacity;
    volatile ULONG write_index;
    volatile ULONG read_index;
    volatile LONG stop_requested;
    volatile LONG broker_status;
    ULONG error_status;
    ULONG reserved;
    ULONG64 packet_count;
    ULONG64 byte_count;
    ULONG64 dropped_count;
    ULONG current_file_index;
    ULONG reserved2;
    WCHAR box_name[BOXNAME_COUNT];
    WCHAR sid_string[96];
    CAPTURE_PACKET_RECORD records[1];

} CAPTURE_BROKER_SECTION;


#pragma pack(pop)


#define CAPTURE_BROKER_SECTION_BASE_SIZE \
    ((ULONG)FIELD_OFFSET(CAPTURE_BROKER_SECTION, records))
#define CAPTURE_BROKER_SECTION_SIZE(capacity) \
    (CAPTURE_BROKER_SECTION_BASE_SIZE + \
     (ULONG)(capacity) * (ULONG)sizeof(CAPTURE_PACKET_RECORD))


#ifdef __cplusplus
static_assert(sizeof(CAPTURE_PACKET_RECORD) == 1600,
              "broker packet record size changed");
static_assert(CAPTURE_BROKER_SECTION_BASE_SIZE % 8 == 0,
              "broker section header alignment changed");
#endif


#endif /* _MY_CAPTUREBROKERWIRE_H */
