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

#include "capture_queue.h"

#include <stddef.h>

#ifndef KERNEL_MODE
#include <string.h>
#endif


#ifdef KERNEL_MODE
#define CaptureQueue_Zero(ptr, size) RtlZeroMemory((ptr), (size))
#define CaptureQueue_Copy(dst, src, size) RtlCopyMemory((dst), (src), (size))
#else
#define CaptureQueue_Zero(ptr, size) memset((ptr), 0, (size))
#define CaptureQueue_Copy(dst, src, size) memcpy((dst), (src), (size))
#endif


static void CaptureQueue_AddDrops(CAPTURE_QUEUE *queue, ULONG64 count)
{
    const ULONG64 maximum = (ULONG64)-1;
    if (maximum - queue->dropped_count < count)
        queue->dropped_count = maximum;
    else
        queue->dropped_count += count;
}


//---------------------------------------------------------------------------
// CaptureQueue_Create
//---------------------------------------------------------------------------


CAPTURE_QUEUE *CaptureQueue_Create(
    ULONG capacity, CAPTURE_QUEUE_ALLOC allocFunction)
{
    const SIZE_T headerSize = offsetof(CAPTURE_QUEUE, records);

    if (! capacity || ! allocFunction ||
            (SIZE_T)capacity > (((SIZE_T)-1 - headerSize) /
                                sizeof(CAPTURE_QUEUE_RECORD))) {
        return NULL;
    }

    const SIZE_T allocationSize = headerSize +
        (SIZE_T)capacity * sizeof(CAPTURE_QUEUE_RECORD);
    CAPTURE_QUEUE *queue = (CAPTURE_QUEUE *)allocFunction(allocationSize);
    if (! queue)
        return NULL;

    CaptureQueue_Zero(queue, allocationSize);
    queue->capacity = capacity;
    queue->next_sequence = 1;
    return queue;
}


//---------------------------------------------------------------------------
// CaptureQueue_Destroy
//---------------------------------------------------------------------------


void CaptureQueue_Destroy(
    CAPTURE_QUEUE *queue, CAPTURE_QUEUE_FREE freeFunction)
{
    if (queue && freeFunction)
        freeFunction(queue);
}


//---------------------------------------------------------------------------
// CaptureQueue_Reset
//---------------------------------------------------------------------------


void CaptureQueue_Reset(CAPTURE_QUEUE *queue)
{
    if (! queue || ! queue->capacity)
        return;

    CaptureQueue_Zero(
        queue->records,
        (SIZE_T)queue->capacity * sizeof(CAPTURE_QUEUE_RECORD));
    queue->head = 0;
    queue->count = 0;
    queue->dropped_count = 0;
    if (! queue->next_sequence)
        queue->next_sequence = 1;
}


//---------------------------------------------------------------------------
// CaptureQueue_Push
//---------------------------------------------------------------------------


BOOLEAN CaptureQueue_Push(
    CAPTURE_QUEUE *queue, const CAPTURE_QUEUE_RECORD *record)
{
    if (! queue || ! queue->capacity || ! record)
        return FALSE;

    if (! queue->next_sequence) {
        CaptureQueue_AddDrops(queue, queue->count);
        queue->head = 0;
        queue->count = 0;
        queue->next_sequence = 1;
    }

    ULONG index;
    if (queue->count == queue->capacity) {
        index = queue->head;
        queue->head = (queue->head + 1) % queue->capacity;
        CaptureQueue_AddDrops(queue, 1);
    }
    else {
        index = (queue->head + queue->count) % queue->capacity;
        ++queue->count;
    }

    CaptureQueue_Copy(
        &queue->records[index], record, sizeof(CAPTURE_QUEUE_RECORD));
    queue->records[index].sequence = queue->next_sequence;

    if (queue->next_sequence == (ULONG64)-1)
        queue->next_sequence = 0;
    else
        ++queue->next_sequence;

    return TRUE;
}


//---------------------------------------------------------------------------
// CaptureQueue_Drain
//---------------------------------------------------------------------------


ULONG CaptureQueue_Drain(
    CAPTURE_QUEUE *queue,
    CAPTURE_QUEUE_RECORD *records,
    ULONG maxRecords,
    ULONG64 *nextSequence,
    ULONG64 *oldestSequence,
    ULONG64 *newestSequence,
    ULONG64 *droppedCount,
    ULONG *remainingRecords)
{
    ULONG64 oldest = 0;
    ULONG64 newest = 0;

    if (nextSequence)
        *nextSequence = 0;
    if (oldestSequence)
        *oldestSequence = 0;
    if (newestSequence)
        *newestSequence = 0;
    if (droppedCount)
        *droppedCount = 0;
    if (remainingRecords)
        *remainingRecords = 0;

    if (! queue || ! queue->capacity)
        return 0;

    if (droppedCount)
        *droppedCount = queue->dropped_count;

    if (! queue->count)
        return 0;

    oldest = queue->records[queue->head].sequence;
    newest = queue->records[
        (queue->head + queue->count - 1) % queue->capacity].sequence;

    if (oldestSequence)
        *oldestSequence = oldest;
    if (newestSequence)
        *newestSequence = newest;
    if (! records || ! maxRecords) {
        if (remainingRecords)
            *remainingRecords = queue->count;
        return 0;
    }

    ULONG returned = queue->count;
    if (returned > maxRecords)
        returned = maxRecords;

    for (ULONG offset = 0; offset < returned; ++offset) {
        const CAPTURE_QUEUE_RECORD *record =
            &queue->records[(queue->head + offset) % queue->capacity];
        CaptureQueue_Copy(
            &records[offset], record, sizeof(CAPTURE_QUEUE_RECORD));
    }

    if (nextSequence)
        *nextSequence = records[returned - 1].sequence;

    queue->head = (queue->head + returned) % queue->capacity;
    queue->count -= returned;
    if (! queue->count)
        queue->head = 0;
    if (remainingRecords)
        *remainingRecords = queue->count;

    return returned;
}
