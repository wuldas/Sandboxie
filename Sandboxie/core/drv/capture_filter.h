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
// Capture Connection Filter
//---------------------------------------------------------------------------

#ifndef _MY_CAPTUREFILTER_H
#define _MY_CAPTUREFILTER_H


#if defined(KERNEL_MODE) || defined(_NTDDK_) || defined(_NTIFS_) || \
        defined(_WDMDDK_)
#include <ntddk.h>
#else
#include <windows.h>
#endif

#include "../../common/defines.h"


#define CAPTURE_FILTER_SCOPE_BOX                1
#define CAPTURE_FILTER_SCOPE_PROCESS            2
#define CAPTURE_FILTER_FLAG_INCLUDE_FUTURE      0x00000001
#define CAPTURE_FILTER_FLAG_INCLUDE_LOOPBACK    0x00000002


typedef struct _CAPTURE_FILTER_PROCESS_KEY {

    ULONG process_id;
    ULONG reserved;
    ULONG64 process_create_time;

} CAPTURE_FILTER_PROCESS_KEY;


typedef struct _CAPTURE_FILTER_TARGET {

    ULONG scope;
    ULONG flags;
    ULONG process_id;
    ULONG session_id;
    ULONG64 process_create_time;
    WCHAR box_name[BOXNAME_COUNT];
    WCHAR sid_string[96];
    ULONG initial_process_count;
    const CAPTURE_FILTER_PROCESS_KEY *initial_processes;

} CAPTURE_FILTER_TARGET;


typedef struct _CAPTURE_FILTER_IDENTITY {

    ULONG process_id;
    ULONG session_id;
    ULONG64 process_create_time;
    BOOLEAN loopback;
    WCHAR box_name[BOXNAME_COUNT];
    WCHAR sid_string[96];

} CAPTURE_FILTER_IDENTITY;


BOOLEAN CaptureFilter_Matches(
    const CAPTURE_FILTER_TARGET *target,
    const CAPTURE_FILTER_IDENTITY *identity);


#endif /* _MY_CAPTUREFILTER_H */
