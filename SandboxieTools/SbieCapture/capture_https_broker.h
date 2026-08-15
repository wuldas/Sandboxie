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
// Broker HTTPS listen helper -- process-mode MITM beside PCAPNG drain
//---------------------------------------------------------------------------

#ifndef _MY_CAPTURE_HTTPS_BROKER_H
#define _MY_CAPTURE_HTTPS_BROKER_H

#include "https_mitm.h"
#include "capture_broker.h"

typedef struct _CAPTURE_HTTPS_OPTIONS {

    HANDLE har_file;
    HANDLE ca_file;
    BOOL test_preamble;
    BOOL redact;
    BOOL include_bodies;
    HTTPS_REDIRECT_CONTEXT expected_context;

} CAPTURE_HTTPS_OPTIONS;

typedef struct _CAPTURE_HTTPS_RUNTIME CAPTURE_HTTPS_RUNTIME;

#ifdef __cplusplus
extern "C" {
#endif

CAPTURE_HTTPS_RUNTIME *CaptureHttps_Start(
    CAPTURE_BROKER_SECTION *section,
    const CAPTURE_HTTPS_OPTIONS *options);

USHORT CaptureHttps_ListenPort(const CAPTURE_HTTPS_RUNTIME *runtime);

void CaptureHttps_Stop(CAPTURE_HTTPS_RUNTIME *runtime);

#ifdef __cplusplus
}
#endif

#endif /* _MY_CAPTURE_HTTPS_BROKER_H */
