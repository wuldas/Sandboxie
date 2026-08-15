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
// Capture Packet Queue -- fixed-size bounded ring with snaplen payload
//---------------------------------------------------------------------------

#ifndef _MY_CAPTUREPACKET_H
#define _MY_CAPTUREPACKET_H


#if defined(KERNEL_MODE) || defined(_NTDDK_) || defined(_NTIFS_) || \
        defined(_WDMDDK_)
#include <ntddk.h>
#else
#include <windows.h>
#endif


#define CAPTURE_PACKET_SNAPLEN_MAX              1514
#define CAPTURE_PACKET_LAYER_TRANSPORT          1
#define CAPTURE_PACKET_LAYER_STREAM             2
#define CAPTURE_PACKET_LAYER_DATAGRAM           3
#define CAPTURE_PACKET_DIRECTION_OUTBOUND       1
#define CAPTURE_PACKET_DIRECTION_INBOUND        2
#define CAPTURE_ADDRESS_FAMILY_IPV4             2
#define CAPTURE_ADDRESS_FAMILY_IPV6             23


typedef struct _CAPTURE_PACKET_RECORD {

    ULONG64 sequence;
    ULONG64 timestamp;
    ULONG64 process_create_time;
    ULONG process_id;
    ULONG session_id;
    USHORT address_family;
    UCHAR protocol;
    UCHAR direction;
    UCHAR layer;
    UCHAR loopback;
    USHORT local_port;
    USHORT remote_port;
    USHORT reserved1;
    ULONG original_length;
    ULONG captured_length;
    UCHAR local_address[16];
    UCHAR remote_address[16];
    UCHAR data[CAPTURE_PACKET_SNAPLEN_MAX];
    UCHAR reserved2[2];

} CAPTURE_PACKET_RECORD;


typedef struct _CAPTURE_PACKET_QUEUE {

    ULONG capacity;
    ULONG head;
    ULONG count;
    ULONG64 next_sequence;
    ULONG64 dropped_count;
    CAPTURE_PACKET_RECORD records[1];

} CAPTURE_PACKET_QUEUE;


typedef void *(*CAPTURE_PACKET_ALLOC)(SIZE_T size);
typedef void (*CAPTURE_PACKET_FREE)(void *ptr);


CAPTURE_PACKET_QUEUE *CapturePacketQueue_Create(
    ULONG capacity, CAPTURE_PACKET_ALLOC allocFunction);

void CapturePacketQueue_Destroy(
    CAPTURE_PACKET_QUEUE *queue, CAPTURE_PACKET_FREE freeFunction);

void CapturePacketQueue_Reset(CAPTURE_PACKET_QUEUE *queue);

BOOLEAN CapturePacketQueue_Push(
    CAPTURE_PACKET_QUEUE *queue, const CAPTURE_PACKET_RECORD *record);

ULONG CapturePacketQueue_Drain(
    CAPTURE_PACKET_QUEUE *queue,
    CAPTURE_PACKET_RECORD *records,
    ULONG maxRecords,
    ULONG64 *nextSequence,
    ULONG64 *oldestSequence,
    ULONG64 *newestSequence,
    ULONG64 *droppedCount,
    ULONG *remainingRecords);


#endif /* _MY_CAPTUREPACKET_H */
