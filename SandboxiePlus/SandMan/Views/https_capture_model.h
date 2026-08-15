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
// HTTPS capture view model -- no Qt, no OpenSSL
//---------------------------------------------------------------------------

#ifndef _MY_HTTPS_CAPTURE_MODEL_H
#define _MY_HTTPS_CAPTURE_MODEL_H

#include <stddef.h>
#include <wchar.h>

#ifdef _WIN32
#ifndef _WINDEF_
typedef unsigned long ULONG;
typedef int BOOL;
#endif
#ifndef WCHAR
typedef wchar_t WCHAR;
#endif
#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif
#else
typedef unsigned long ULONG;
typedef int BOOL;
typedef wchar_t WCHAR;
#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif
#endif

#define HTTPS_CAPTURE_CAP_INSPECTION    0x00000008ul
#define HTTPS_CAPTURE_CAP_PCAPNG        0x00000010ul
#define HTTPS_CAPTURE_CAP_HAR           0x00000020ul
#define HTTPS_CAPTURE_CAP_REQUIRED \
    (HTTPS_CAPTURE_CAP_INSPECTION | HTTPS_CAPTURE_CAP_PCAPNG | HTTPS_CAPTURE_CAP_HAR)

#define HTTPS_CAPTURE_MAX_ROWS          2000
#define HTTPS_CAPTURE_COL_COUNT         9

typedef struct _HTTPS_CAPTURE_ROW {

    char time[64];
    ULONG pid;
    char process[64];
    char method[16];
    ULONG status;
    char host[256];
    char path[256];
    char tls[16];
    BOOL pinning_failed;

} HTTPS_CAPTURE_ROW;


#ifdef __cplusplus
extern "C" {
#endif

BOOL HttpsCapture_CanStart(
    ULONG capabilityFlags,
    const WCHAR *pcapPath,
    const WCHAR *harPath);

int HttpsCapture_ParseEntry(
    const char *json,
    HTTPS_CAPTURE_ROW *row);

int HttpsCapture_Enqueue(
    HTTPS_CAPTURE_ROW *rows,
    ULONG *count,
    ULONG capacity,
    const HTTPS_CAPTURE_ROW *row);

int HttpsCapture_FormatStatus(
    char *buffer,
    ULONG bufferSize,
    ULONG exchanges,
    ULONG dropped,
    const char *harPath);

#ifdef __cplusplus
}
#endif

#endif /* _MY_HTTPS_CAPTURE_MODEL_H */
