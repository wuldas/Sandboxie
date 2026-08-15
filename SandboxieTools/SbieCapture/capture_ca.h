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
// Session capture CA -- public API, no OpenSSL types
//---------------------------------------------------------------------------

#ifndef _MY_CAPTURE_CA_H
#define _MY_CAPTURE_CA_H

#include <windows.h>

#define CAPTURE_CA_OK               0
#define CAPTURE_CA_ERROR            (-1)

typedef struct _CAPTURE_CA CAPTURE_CA;

#ifdef __cplusplus
extern "C" {
#endif

CAPTURE_CA *CaptureCa_Create(void);
void CaptureCa_Free(CAPTURE_CA *ca);

int CaptureCa_ExportPublicPem(
    const CAPTURE_CA *ca,
    char *buffer,
    ULONG capacity,
    ULONG *length);

int CaptureCa_WritePublicPemPath(const CAPTURE_CA *ca, const WCHAR *path);

#ifdef __cplusplus
}
#endif

#endif /* _MY_CAPTURE_CA_H */
