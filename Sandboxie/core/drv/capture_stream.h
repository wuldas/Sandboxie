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
// Capture Stream Queue -- same bounded ring, application-data layer tag
//---------------------------------------------------------------------------

#ifndef _MY_CAPTURESTREAM_H
#define _MY_CAPTURESTREAM_H


#include "capture_packet.h"


typedef CAPTURE_PACKET_RECORD CAPTURE_STREAM_RECORD;
typedef CAPTURE_PACKET_QUEUE CAPTURE_STREAM_QUEUE;


#define CaptureStreamQueue_Create       CapturePacketQueue_Create
#define CaptureStreamQueue_Destroy      CapturePacketQueue_Destroy
#define CaptureStreamQueue_Reset        CapturePacketQueue_Reset
#define CaptureStreamQueue_Push         CapturePacketQueue_Push
#define CaptureStreamQueue_Drain        CapturePacketQueue_Drain


#endif /* _MY_CAPTURESTREAM_H */
