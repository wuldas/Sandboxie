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
// Capture Connection Queue -- fixed-size bounded ring
//---------------------------------------------------------------------------

#ifndef _MY_CAPTUREQUEUE_H
#define _MY_CAPTUREQUEUE_H


#if defined(KERNEL_MODE) || defined(_NTDDK_) || defined(_NTIFS_) || \
        defined(_WDMDDK_)
#include <ntddk.h>
#else
#include <windows.h>
#endif

//---------------------------------------------------------------------------
// Structures and Types
//---------------------------------------------------------------------------


#define CAPTURE_QUEUE_EVENT_CONNECT             1
#define CAPTURE_QUEUE_EVENT_ACCEPT              2

#define CAPTURE_QUEUE_DIRECTION_OUTBOUND        1
#define CAPTURE_QUEUE_DIRECTION_INBOUND         2


typedef struct _CAPTURE_QUEUE_RECORD {

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

} CAPTURE_QUEUE_RECORD;


typedef struct _CAPTURE_QUEUE {

    ULONG capacity;
    ULONG head;
    ULONG count;
    ULONG64 next_sequence;
    ULONG64 dropped_count;
    CAPTURE_QUEUE_RECORD records[1];

} CAPTURE_QUEUE;


typedef void *(*CAPTURE_QUEUE_ALLOC)(SIZE_T size);
typedef void (*CAPTURE_QUEUE_FREE)(void *ptr);


//---------------------------------------------------------------------------
// Functions
//---------------------------------------------------------------------------


CAPTURE_QUEUE *CaptureQueue_Create(
    ULONG capacity, CAPTURE_QUEUE_ALLOC allocFunction);

void CaptureQueue_Destroy(
    CAPTURE_QUEUE *queue, CAPTURE_QUEUE_FREE freeFunction);

void CaptureQueue_Reset(CAPTURE_QUEUE *queue);

BOOLEAN CaptureQueue_Push(
    CAPTURE_QUEUE *queue, const CAPTURE_QUEUE_RECORD *record);

ULONG CaptureQueue_Drain(
    CAPTURE_QUEUE *queue,
    CAPTURE_QUEUE_RECORD *records,
    ULONG maxRecords,
    ULONG64 *nextSequence,
    ULONG64 *oldestSequence,
    ULONG64 *newestSequence,
    ULONG64 *droppedCount,
    ULONG *remainingRecords);


//---------------------------------------------------------------------------


#endif /* _MY_CAPTUREQUEUE_H */
