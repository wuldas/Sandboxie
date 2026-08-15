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
// Capture Connection Audit
//---------------------------------------------------------------------------

#ifndef _MY_CAPTURE_H
#define _MY_CAPTURE_H


#include "capture_filter.h"
#include "capture_queue.h"
#include "capture_packet.h"
#include "capture_stream.h"


BOOLEAN Capture_Init(void);

void Capture_Unload(void);

void Capture_Reset(void);

void Capture_RecordEvent(
    const CAPTURE_FILTER_IDENTITY *identity,
    const CAPTURE_QUEUE_RECORD *record);

UINT64 Capture_CreateFlowContext(
    const CAPTURE_FILTER_IDENTITY *identity,
    const CAPTURE_PACKET_RECORD *templateRecord,
    UINT64 flowId,
    UINT16 layerId,
    UINT32 calloutId);

void Capture_DeleteFlowContext(UINT64 flowContext);

UINT64 Capture_LookupFlowContext(
    UINT64 flowId,
    UINT16 layerId,
    UINT32 calloutId);

void Capture_CountDroppedIdentity(
    const CAPTURE_FILTER_IDENTITY *identity);

void Capture_RecordPayloadByFlow(
    UINT64 flowContext,
    const UCHAR *data,
    ULONG dataLength,
    ULONG originalLength,
    UCHAR layer);


#endif /* _MY_CAPTURE_H */
