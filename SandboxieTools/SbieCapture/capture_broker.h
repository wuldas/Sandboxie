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
// SbieCapture broker -- bounded user-mode packet drain
//---------------------------------------------------------------------------

#ifndef _MY_CAPTUREBROKER_H
#define _MY_CAPTUREBROKER_H


#include <windows.h>

#include "../../Sandboxie/core/svc/capturebrokerwire.h"
#include "pcapng.h"


#define CAPTURE_BROKER_OK                 0
#define CAPTURE_BROKER_ERROR              1
#define CAPTURE_BROKER_INVALID            2
#define CAPTURE_BROKER_SNAP_LENGTH_MIN    64
#define CAPTURE_BROKER_SNAP_LENGTH_MAX    1514
#define CAPTURE_BROKER_MAX_SECONDS        86400
#define CAPTURE_BROKER_MAX_ROTATE_COUNT   64


typedef struct _CAPTURE_BROKER_OPTIONS {

    HANDLE output_file;
    const WCHAR *rotation_path;
    HANDLE stop_event;
    ULONG snap_length;
    ULONG max_file_bytes;
    ULONG max_seconds;
    ULONG rotate_count;

} CAPTURE_BROKER_OPTIONS;


int CaptureBroker_Run(
    CAPTURE_BROKER_SECTION *section,
    const CAPTURE_BROKER_OPTIONS *options);


#endif /* _MY_CAPTUREBROKER_H */
